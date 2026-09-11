use crate::{engine::Engine, model::Session};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tower_http::services::{ServeDir, ServeFile};
use uuid::Uuid;

pub struct Auth {
    user: String,
    password: [u8; 32],
    tokens: Mutex<HashMap<[u8; 32], Instant>>,
    attempts: Mutex<Vec<Instant>>,
}
fn digest(s: &str) -> [u8; 32] {
    Sha256::digest(s.as_bytes()).into()
}
impl Auth {
    pub fn new(user: String, password: String) -> anyhow::Result<Self> {
        anyhow::ensure!(
            password.len() >= 16,
            "MASTER_PASSWORD must have at least 16 characters"
        );
        Ok(Self {
            user,
            password: digest(&password),
            tokens: Default::default(),
            attempts: Default::default(),
        })
    }
    fn login(&self, user: &str, password: &str) -> Result<String, ApiError> {
        let mut attempts = self.attempts.lock().unwrap();
        attempts.retain(|t| t.elapsed() < Duration::from_secs(60));
        if attempts.len() >= 10 {
            return Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many login attempts; wait one minute".into(),
            ));
        }
        attempts.push(Instant::now());
        let valid =
            digest(user).ct_eq(&digest(&self.user)) & digest(password).ct_eq(&self.password);
        if !bool::from(valid) {
            return Err(ApiError(
                StatusCode::UNAUTHORIZED,
                "Invalid username or password".into(),
            ));
        }
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let mut tokens = self.tokens.lock().unwrap();
        tokens.retain(|_, t| t.elapsed() < Duration::from_secs(8 * 3600));
        if tokens.len() >= 100 {
            tokens.clear();
        }
        tokens.insert(digest(&token), Instant::now());
        Ok(token)
    }
    fn valid(&self, token: &str) -> bool {
        let mut tokens = self.tokens.lock().unwrap();
        tokens.retain(|_, t| t.elapsed() < Duration::from_secs(8 * 3600));
        tokens.contains_key(&digest(token))
    }
}
#[derive(Clone)]
pub struct Web {
    pub engine: Arc<Engine>,
    pub auth: Arc<Auth>,
}

pub struct ApiError(StatusCode, String);
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        Self(StatusCode::CONFLICT, e.to_string())
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":self.1}))).into_response()
    }
}
type Api<T> = Result<Json<T>, ApiError>;
fn token(req: &Request) -> Option<&str> {
    req.headers()
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|s| s.trim().strip_prefix("iso_session="))
}
async fn protect(State(web): State<Web>, req: Request, next: Next) -> Response {
    if req.method() != axum::http::Method::GET && req.method() != axum::http::Method::HEAD {
        let custom = req.headers().get("x-iso-master").is_some_and(|h| h == "1");
        let origin = req
            .headers()
            .get(header::ORIGIN)
            .map(|h| h == web.engine.cfg.public_origin.as_str())
            .unwrap_or(true);
        let same_site = !req
            .headers()
            .get("sec-fetch-site")
            .is_some_and(|h| h == "cross-site");
        if !custom || !origin || !same_site {
            return ApiError(
                StatusCode::FORBIDDEN,
                "Cross-site or missing CSRF header".into(),
            )
            .into_response();
        }
    }
    if req.uri().path() != "/api/login" && !token(&req).is_some_and(|t| web.auth.valid(t)) {
        return ApiError(StatusCode::UNAUTHORIZED, "Sign in required".into()).into_response();
    }
    next.run(req).await
}
async fn headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    for (name, value) in [
        (
            "content-security-policy",
            "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        ),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("cache-control", "no-store"),
    ] {
        res.headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    res
}
#[derive(Deserialize)]
struct Login {
    username: String,
    password: String,
}
async fn login(State(web): State<Web>, Json(data): Json<Login>) -> Result<Response, ApiError> {
    let token = web.auth.login(&data.username, &data.password)?;
    let secure = if web.engine.cfg.secure_cookie {
        "; Secure"
    } else {
        ""
    };
    let cookie =
        format!("iso_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800{secure}");
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({"ok":true}))).into_response())
}
async fn logout(State(web): State<Web>, req: Request) -> Response {
    if let Some(t) = token(&req) {
        web.auth.tokens.lock().unwrap().remove(&digest(t));
    }
    (
        [(
            header::SET_COOKIE,
            "iso_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        )],
        Json(json!({"ok":true})),
    )
        .into_response()
}
async fn me(State(web): State<Web>) -> Json<Value> {
    Json(
        json!({"user":web.auth.user,"demo":web.engine.cfg.demo,"idle_seconds":web.engine.cfg.idle_seconds}),
    )
}
async fn sessions(State(web): State<Web>) -> Api<Vec<Session>> {
    Ok(Json(web.engine.store.list()?))
}
#[derive(Deserialize)]
struct New {
    name: String,
}
async fn create(State(web): State<Web>, Json(data): Json<New>) -> Api<Session> {
    Ok(Json(web.engine.create(&data.name).await?))
}
#[derive(Deserialize)]
struct Cursor {
    #[serde(default)]
    after: u64,
}
async fn events(
    State(web): State<Web>,
    Path(id): Path<Uuid>,
    Query(cursor): Query<Cursor>,
) -> Api<Value> {
    let id = id.to_string();
    let session = web
        .engine
        .store
        .get(&id)
        .map_err(|_| ApiError(StatusCode::NOT_FOUND, "Session not found".into()))?;
    Ok(Json(
        json!({"session":session,"events":web.engine.store.events(&id,cursor.after)?}),
    ))
}
#[derive(Deserialize)]
struct Prompt {
    message: String,
}
async fn prompt(
    State(web): State<Web>,
    Path(id): Path<Uuid>,
    Json(data): Json<Prompt>,
) -> Api<Value> {
    web.engine.prompt(&id.to_string(), &data.message).await?;
    Ok(Json(json!({"ok":true})))
}
async fn action(State(web): State<Web>, Path((id, action)): Path<(Uuid, String)>) -> Api<Value> {
    let id = id.to_string();
    match action.as_str() {
        "sleep" => web.engine.sleep(&id).await?,
        "abort" => web.engine.abort(&id).await?,
        "recover" => {
            web.engine.recover_session(&id).await?;
        }
        "reconcile" => {
            web.engine.reconcile(&id).await?;
        }
        _ => {
            return Err(ApiError(
                StatusCode::NOT_FOUND,
                "Unknown session action".into(),
            ));
        }
    }
    Ok(Json(json!({"ok":true})))
}
async fn close(State(web): State<Web>, Path(id): Path<Uuid>) -> Api<Value> {
    web.engine.close_session(&id.to_string()).await?;
    Ok(Json(json!({"ok":true})))
}
async fn fleet(State(web): State<Web>) -> Json<Value> {
    Json(json!({"planes":web.engine.fleet().await}))
}

pub fn router(web: Web) -> Router {
    let api = Router::new()
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/sessions", get(sessions).post(create))
        .route("/api/sessions/{id}", delete(close))
        .route("/api/sessions/{id}/events", get(events))
        .route("/api/sessions/{id}/prompt", post(prompt))
        .route("/api/sessions/{id}/actions/{action}", post(action))
        .route("/api/fleet", get(fleet))
        .layer(middleware::from_fn_with_state(web.clone(), protect));
    let ui = ServeDir::new(&web.engine.cfg.ui_dir)
        .fallback(ServeFile::new(web.engine.cfg.ui_dir.join("index.html")));
    api.fallback_service(ui)
        .layer(DefaultBodyLimit::max(128 * 1024))
        .layer(middleware::from_fn(headers))
        .with_state(web)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{Config, PlaneConfig},
        store::Store,
    };
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    #[tokio::test]
    async fn auth_csrf_and_cookie_flow() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config {
            demo: true,
            data_dir: dir.path().into(),
            planes: vec![PlaneConfig {
                id: "demo".into(),
                server: "demo".into(),
                creds: "unused".into(),
                client: "unused".into(),
                template: "debian".into(),
                egress: "deny".into(),
                principal: None,
                allow: vec![],
                max_vms: 1,
            }],
            ..Config::default()
        };
        let store = Arc::new(Store::open(&dir.path().join("db")).unwrap());
        let app = router(Web {
            engine: Engine::new(cfg, store).unwrap(),
            auth: Arc::new(Auth::new("admin".into(), "test-password-long".into()).unwrap()),
        });
        let req = || {
            Request::builder()
                .method("POST")
                .uri("/api/login")
                .header("content-type", "application/json")
        };
        let body = || Body::from(r#"{"username":"admin","password":"test-password-long"}"#);
        assert_eq!(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/me")
                        .body(Body::empty())
                        .unwrap()
                )
                .await
                .unwrap()
                .status(),
            401
        );
        assert_eq!(
            app.clone()
                .oneshot(req().body(body()).unwrap())
                .await
                .unwrap()
                .status(),
            403
        );
        assert_eq!(
            app.clone()
                .oneshot(
                    req()
                        .header("x-iso-master", "1")
                        .header("origin", "https://evil.test")
                        .body(body())
                        .unwrap()
                )
                .await
                .unwrap()
                .status(),
            403
        );
        let response = app
            .clone()
            .oneshot(req().header("x-iso-master", "1").body(body()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            cookie.contains("HttpOnly")
                && cookie.contains("SameSite=Strict")
                && cookie.contains("Secure")
        );
        assert_eq!(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/me")
                        .header("cookie", &cookie)
                        .body(Body::empty())
                        .unwrap()
                )
                .await
                .unwrap()
                .status(),
            200
        );
        assert_eq!(
            app.clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/logout")
                        .header("x-iso-master", "1")
                        .header("cookie", &cookie)
                        .body(Body::empty())
                        .unwrap()
                )
                .await
                .unwrap()
                .status(),
            200
        );
        assert_eq!(
            app.oneshot(
                Request::builder()
                    .uri("/api/me")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
            401
        );
    }
}
