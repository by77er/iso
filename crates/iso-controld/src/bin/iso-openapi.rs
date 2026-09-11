//! Print the admin API's OpenAPI document (JSON) and exit. No root, no host
//! state: the document is derived from the handler annotations.

use utoipa::OpenApi as _;

fn main() {
    println!("{}", iso_controld::http::ApiDoc::openapi().to_pretty_json().expect("serialize openapi"));
}
