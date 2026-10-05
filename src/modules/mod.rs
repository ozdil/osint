pub mod domain;
pub mod history;
pub mod identity;
pub mod ip;
pub mod media;
pub mod web;

use crate::{config::Config, http::Http};
use anyhow::{bail, Result};
use serde_json::Value;

pub const NAMES: &[&str] = &["domain", "ip", "web", "user", "email", "phone", "media", "history"];

/// CLI ve web paneli icin ortak modul dagiticisi.
pub async fn dispatch(http: &Http, cfg: &Config, module: &str, target: &str) -> Result<Value> {
    match module {
        "domain" => domain::run(http, target).await,
        "ip" => ip::run(http, target).await,
        "web" => web::run(http, target).await,
        "user" => identity::username(http, target).await,
        "email" => identity::email(http, cfg, target).await,
        "phone" => identity::phone(target),
        "media" => media::run(http, cfg, target).await,
        "history" => history::run(http, cfg, target).await,
        _ => bail!("Bilinmeyen modul: {module}. Gecerli: {}", NAMES.join(", ")),
    }
}
