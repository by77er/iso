//! iso-policy — the egress rule language and its matcher. Pure: no I/O, no
//! async. Consumed by the proxy (both phases), the DNS redirect for Allow
//! mode, the control plane's input validation, and the metadata endpoint
//! that describes a VM's policy to the guest. [`signed`] is how a fleet
//! vouches for a policy so a proxy tier can trust it without trusting the
//! host that relays it.
//!
//! ## Grammar
//!
//! ```text
//! rule    := ("allow" | "deny") ws pattern
//! pattern := scheme "://" host [":" port] path
//! scheme  := "https" | "wss"          both TLS; wss matches only Upgrade requests
//! host    := label ("." label)*       exact
//!          | "*." label ("." label)*  one or more leading labels, never the apex
//! path    := "/" segment*             "*" matches within one segment
//!                                     "**" matches across segments (last only)
//! ```
//!
//! ## Semantics
//!
//! - Default deny: a request matching no rule is denied.
//! - Explicit deny wins: any matching deny rule denies, whatever allow rules
//!   say. Rules are therefore a set; order never matters.
//! - Two phases. The **host phase** runs at SNI time, before TLS is
//!   terminated: the SNI must match the host of at least one allow rule. The
//!   **URI phase** runs per request, after the authority check and before
//!   credential injection.
//! - Query strings are never matched; callers strip them.
//! - The legacy allow-list is sugar: `allow: ["h"]` means
//!   `allow https://h/**` plus `allow wss://h/**`.

pub mod signed;

use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("rule must start with `allow` or `deny`: {0:?}")]
    Action(String),
    #[error("pattern must be `https://host/path` or `wss://host/path`: {0:?}")]
    Scheme(String),
    #[error("invalid host {0:?}: {1}")]
    Host(String, &'static str),
    #[error("invalid port in {0:?}")]
    Port(String),
    #[error("invalid path {0:?}: {1}")]
    Path(String, &'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    /// A plain request over TLS.
    Https,
    /// A WebSocket upgrade request over TLS.
    Wss,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Https => "https",
            Scheme::Wss => "wss",
        }
    }
}

/// A host pattern: an exact name, or `*.` followed by a suffix that must be
/// preceded by at least one more label.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HostPattern {
    Exact(String),
    /// `*.suffix`: matches `a.suffix`, `a.b.suffix`, never `suffix`.
    Subdomains(String),
}

impl HostPattern {
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        let raw = s.to_string();
        let s = s.to_ascii_lowercase();
        if s.is_empty() {
            return Err(ParseError::Host(raw, "empty"));
        }
        let (wild, name) = match s.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, s.as_str()),
        };
        if name.is_empty() || name.contains('*') {
            return Err(ParseError::Host(raw, "`*` is only valid as a leading `*.`"));
        }
        if name.starts_with('.') || name.ends_with('.') || name.contains("..") {
            return Err(ParseError::Host(raw, "malformed labels"));
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return Err(ParseError::Host(raw, "only letters, digits, `-` and `.`"));
        }
        Ok(if wild {
            HostPattern::Subdomains(name.to_string())
        } else {
            HostPattern::Exact(name.to_string())
        })
    }

    pub fn matches(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        match self {
            HostPattern::Exact(h) => *h == host,
            HostPattern::Subdomains(suffix) => {
                host.len() > suffix.len() + 1
                    && host.ends_with(suffix.as_str())
                    && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
            }
        }
    }

    /// The literal host, when the pattern is not a wildcard. Used by callers
    /// that need to enumerate hosts (the metadata description).
    pub fn literal(&self) -> Option<&str> {
        match self {
            HostPattern::Exact(h) => Some(h),
            HostPattern::Subdomains(_) => None,
        }
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostPattern::Exact(h) => f.write_str(h),
            HostPattern::Subdomains(s) => write!(f, "*.{s}"),
        }
    }
}

/// One path segment pattern.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Seg {
    Lit(String),
    /// `*`: exactly one segment, any content (including empty).
    One,
    /// `**`: zero or more segments; only valid last.
    Rest,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PathPattern {
    segs: Vec<Seg>,
}

impl PathPattern {
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        let raw = s.to_string();
        if !s.starts_with('/') {
            return Err(ParseError::Path(raw, "must start with `/`"));
        }
        if s.contains('?') || s.contains('#') {
            return Err(ParseError::Path(raw, "query and fragment are not matched"));
        }
        let mut segs = Vec::new();
        let parts: Vec<&str> = s[1..].split('/').collect();
        for (i, p) in parts.iter().enumerate() {
            let last = i + 1 == parts.len();
            let seg = match *p {
                "**" => {
                    if !last {
                        return Err(ParseError::Path(raw, "`**` must be the last segment"));
                    }
                    Seg::Rest
                }
                "*" => Seg::One,
                lit => {
                    if lit.contains('*') {
                        return Err(ParseError::Path(raw, "`*` must be a whole segment"));
                    }
                    Seg::Lit(lit.to_string())
                }
            };
            segs.push(seg);
        }
        Ok(PathPattern { segs })
    }

    pub fn matches(&self, path: &str) -> bool {
        let path = path.split('?').next().unwrap_or(path);
        let path = path.strip_prefix('/').unwrap_or(path);
        let parts: Vec<&str> = path.split('/').collect();
        Self::match_from(&self.segs, &parts)
    }

    fn match_from(segs: &[Seg], parts: &[&str]) -> bool {
        match (segs.first(), parts.first()) {
            (None, None) => true,
            (Some(Seg::Rest), _) => true,
            (None, Some(_)) => false,
            (Some(_), None) => false,
            (Some(Seg::One), Some(_)) => Self::match_from(&segs[1..], &parts[1..]),
            (Some(Seg::Lit(l)), Some(p)) => l == p && Self::match_from(&segs[1..], &parts[1..]),
        }
    }
}

impl fmt::Display for PathPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for s in &self.segs {
            f.write_str("/")?;
            match s {
                Seg::Lit(l) => f.write_str(l)?,
                Seg::One => f.write_str("*")?,
                Seg::Rest => f.write_str("**")?,
            }
        }
        Ok(())
    }
}

/// A parsed rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Rule {
    pub action: Action,
    pub scheme: Scheme,
    pub host: HostPattern,
    pub port: Option<u16>,
    pub path: PathPattern,
}

impl Rule {
    /// Parse `allow https://host/path` or `deny wss://host:port/path`.
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        let s = s.trim();
        let (action, rest) = match s.split_once(char::is_whitespace) {
            Some((a, r)) => (a, r.trim_start()),
            None => return Err(ParseError::Action(s.to_string())),
        };
        let action = match action {
            "allow" => Action::Allow,
            "deny" => Action::Deny,
            _ => return Err(ParseError::Action(s.to_string())),
        };
        let (scheme, rest) = match rest.split_once("://") {
            Some(("https", r)) => (Scheme::Https, r),
            Some(("wss", r)) => (Scheme::Wss, r),
            _ => return Err(ParseError::Scheme(rest.to_string())),
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (
                h,
                Some(
                    p.parse::<u16>()
                        .map_err(|_| ParseError::Port(authority.to_string()))?,
                ),
            ),
            None => (authority, None),
        };
        Ok(Rule {
            action,
            scheme,
            host: HostPattern::parse(host)?,
            port,
            path: PathPattern::parse(path)?,
        })
    }

    fn matches(&self, scheme: Scheme, host: &str, port: Option<u16>, path: &str) -> bool {
        self.scheme == scheme
            && self.host.matches(host)
            && self.port.is_none_or(|p| port.is_none_or(|q| p == q))
            && self.path.matches(path)
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let action = match self.action {
            Action::Allow => "allow",
            Action::Deny => "deny",
        };
        write!(f, "{action} {}://{}", self.scheme.as_str(), self.host)?;
        if let Some(p) = self.port {
            write!(f, ":{p}")?;
        }
        write!(f, "{}", self.path)
    }
}

/// The outcome of the URI phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Denied by an explicit rule (its text), or `None` for default deny.
    Deny(Option<String>),
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow)
    }
}

/// A compiled rule set. Cheap to clone (share it in an `Arc` if it is hot).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    pub fn new(rules: Vec<Rule>) -> Self {
        let mut rules = rules;
        rules.sort_by_key(|r| r.to_string());
        rules.dedup();
        Self { rules }
    }

    /// Parse every rule; the first bad one is the error.
    pub fn parse<I, S>(rules: I) -> Result<Self, ParseError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Ok(Self::new(
            rules
                .into_iter()
                .map(|r| Rule::parse(r.as_ref()))
                .collect::<Result<Vec<_>, _>>()?,
        ))
    }

    /// The legacy host allow-list, expanded: each host allows everything over
    /// https and wss.
    pub fn from_allow_list<I, S>(hosts: I) -> Result<Self, ParseError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut rules = Vec::new();
        for h in hosts {
            let host = HostPattern::parse(h.as_ref())?;
            for scheme in [Scheme::Https, Scheme::Wss] {
                rules.push(Rule {
                    action: Action::Allow,
                    scheme,
                    host: host.clone(),
                    port: None,
                    path: PathPattern::parse("/**").unwrap(),
                });
            }
        }
        Ok(Self::new(rules))
    }

    /// `allow` hosts plus explicit `rules`, as the VM record stores them.
    pub fn from_record<A, R, S>(allow: A, rules: R) -> Result<Self, ParseError>
    where
        A: IntoIterator<Item = S>,
        R: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut all = Self::from_allow_list(allow)?.rules;
        all.extend(Self::parse(rules)?.rules);
        Ok(Self::new(all))
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Every rule, as text. The wire form.
    pub fn to_strings(&self) -> Vec<String> {
        self.rules.iter().map(|r| r.to_string()).collect()
    }

    /// Host phase: may a TLS session to `sni` be terminated at all? True when
    /// some allow rule could match a request on that host. A host with only
    /// deny rules is never terminated.
    pub fn host_allowed(&self, sni: &str) -> bool {
        self.rules
            .iter()
            .any(|r| r.action == Action::Allow && r.host.matches(sni))
    }

    /// URI phase. Deny beats allow; nothing matching is denied.
    pub fn evaluate(&self, scheme: Scheme, host: &str, port: Option<u16>, path: &str) -> Decision {
        let mut allowed = false;
        for r in &self.rules {
            if !r.matches(scheme, host, port, path) {
                continue;
            }
            match r.action {
                Action::Deny => return Decision::Deny(Some(r.to_string())),
                Action::Allow => allowed = true,
            }
        }
        if allowed {
            Decision::Allow
        } else {
            Decision::Deny(None)
        }
    }

    /// The literal (non-wildcard) hosts named by allow rules, for callers
    /// that must enumerate: the metadata description of injected headers.
    pub fn literal_allow_hosts(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .rules
            .iter()
            .filter(|r| r.action == Action::Allow)
            .filter_map(|r| r.host.literal().map(str::to_string))
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rs(rules: &[&str]) -> RuleSet {
        RuleSet::parse(rules).unwrap()
    }

    #[test]
    fn parses_and_prints_round_trip() {
        for s in [
            "allow https://api.github.com/**",
            "deny https://api.github.com/user/keys",
            "allow https://*.anthropic.com/v1/messages",
            "allow wss://api.openai.com/v1/realtime",
            "allow https://example.com:8443/*/x/**",
            "deny https://example.com/",
        ] {
            assert_eq!(Rule::parse(s).unwrap().to_string(), s, "{s}");
        }
    }

    #[test]
    fn rejects_malformed_rules() {
        for s in [
            "",
            "permit https://x/",
            "allow http://x/",
            "allow https://*x.com/",
            "allow https://a.*.com/",
            "allow https://x.com/a/**/b",
            "allow https://x.com/a*/b",
            "allow https://x.com:99999/",
            "allow https://x.com/a?b=1",
            "allow https:///",
        ] {
            assert!(Rule::parse(s).is_err(), "{s:?} should not parse");
        }
    }

    #[test]
    fn host_patterns() {
        let w = HostPattern::parse("*.anthropic.com").unwrap();
        assert!(w.matches("api.anthropic.com"));
        assert!(w.matches("a.b.anthropic.com"));
        assert!(w.matches("API.Anthropic.COM."));
        assert!(!w.matches("anthropic.com"));
        assert!(!w.matches("notanthropic.com"));
        assert!(!w.matches("anthropic.com.evil"));
        let e = HostPattern::parse("Api.GitHub.com").unwrap();
        assert!(e.matches("api.github.com"));
        assert!(!e.matches("www.api.github.com"));
    }

    #[test]
    fn path_patterns() {
        let p = |s| PathPattern::parse(s).unwrap();
        assert!(p("/**").matches("/"));
        assert!(p("/**").matches("/a/b/c"));
        assert!(p("/repos/**").matches("/repos"));
        assert!(p("/repos/**").matches("/repos/o/r"));
        assert!(!p("/repos/**").matches("/repository"));
        assert!(p("/user/keys").matches("/user/keys"));
        assert!(p("/user/keys").matches("/user/keys?per_page=5"));
        assert!(!p("/user/keys").matches("/user/keys/1"));
        assert!(p("/v1/*/messages").matches("/v1/x/messages"));
        assert!(!p("/v1/*/messages").matches("/v1/x/y/messages"));
        assert!(p("/").matches("/"));
        assert!(!p("/").matches("/a"));
    }

    #[test]
    fn deny_beats_allow_and_default_is_deny() {
        let r = rs(&[
            "allow https://api.github.com/**",
            "deny https://api.github.com/user/keys",
        ]);
        assert_eq!(
            r.evaluate(Scheme::Https, "api.github.com", None, "/repos/o/r"),
            Decision::Allow
        );
        assert_eq!(
            r.evaluate(Scheme::Https, "api.github.com", None, "/user/keys?x=1"),
            Decision::Deny(Some("deny https://api.github.com/user/keys".into()))
        );
        assert_eq!(
            r.evaluate(Scheme::Https, "api.github.com", None, "/user/keys/1"),
            Decision::Allow
        );
        assert_eq!(
            r.evaluate(Scheme::Https, "github.com", None, "/"),
            Decision::Deny(None)
        );
        // scheme matters
        assert_eq!(
            r.evaluate(Scheme::Wss, "api.github.com", None, "/"),
            Decision::Deny(None)
        );
        // order does not
        let r2 = rs(&[
            "deny https://api.github.com/user/keys",
            "allow https://api.github.com/**",
        ]);
        assert_eq!(r, r2);
    }

    #[test]
    fn host_phase_ignores_deny_only_hosts() {
        let r = rs(&[
            "allow https://*.anthropic.com/v1/messages",
            "deny https://evil.com/**",
        ]);
        assert!(r.host_allowed("api.anthropic.com"));
        assert!(!r.host_allowed("anthropic.com"));
        assert!(!r.host_allowed("evil.com"));
        assert!(!r.host_allowed("unknown.com"));
    }

    #[test]
    fn ports_match_when_given() {
        let r = rs(&["allow https://example.com:8443/**"]);
        assert!(
            r.evaluate(Scheme::Https, "example.com", Some(8443), "/")
                .is_allow()
        );
        assert!(
            !r.evaluate(Scheme::Https, "example.com", Some(443), "/")
                .is_allow()
        );
        // no port known on the request side: the rule's port is not enforced
        assert!(
            r.evaluate(Scheme::Https, "example.com", None, "/")
                .is_allow()
        );
    }

    #[test]
    fn allow_list_sugar_expands_to_both_schemes() {
        let r = RuleSet::from_allow_list(["api.github.com", "*.debian.org"]).unwrap();
        assert_eq!(
            r.to_strings(),
            vec![
                "allow https://*.debian.org/**",
                "allow https://api.github.com/**",
                "allow wss://*.debian.org/**",
                "allow wss://api.github.com/**",
            ]
        );
        assert!(
            r.evaluate(Scheme::Wss, "api.github.com", None, "/ws")
                .is_allow()
        );
        assert!(r.host_allowed("deb.debian.org"));
        assert_eq!(r.literal_allow_hosts(), vec!["api.github.com"]);
        assert!(RuleSet::from_allow_list(["bad host"]).is_err());
    }

    #[test]
    fn from_record_merges_and_dedups() {
        let r = RuleSet::from_record(
            ["api.github.com"],
            [
                "deny https://api.github.com/user/keys",
                "allow https://api.github.com/**",
            ],
        )
        .unwrap();
        assert_eq!(r.rules().len(), 3);
        assert!(
            !r.evaluate(Scheme::Https, "api.github.com", None, "/user/keys")
                .is_allow()
        );
    }
}
