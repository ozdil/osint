//! Yerel web paneli (yalnizca 127.0.0.1).

use crate::{config::Config, correlate, http::Http, modules, pivot, report, store::Store};
use axum::{
    body::Bytes,
    extract::{Path, Query, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

struct App {
    http: Http,
    cfg: Config,
    store: Mutex<Store>,
}

type S = State<Arc<App>>;

fn err(e: impl std::fmt::Display) -> Response {
    let m = e.to_string();
    // Kutuphane hatalarini Turkce ve dogru durum koduna esle
    let (code, msg) = if m.contains("no rows") || m.contains("FOREIGN KEY") {
        (StatusCode::NOT_FOUND, "Vaka bulunamadi".to_string())
    } else {
        (StatusCode::BAD_REQUEST, m)
    };
    (code, Json(json!({"hata": msg}))).into_response()
}

fn lock(a: &App) -> std::sync::MutexGuard<'_, Store> {
    a.store.lock().unwrap_or_else(|p| p.into_inner())
}

/// Govdeyi 64 KiB sinirla ayristirir; hata mesaji Turkce.
#[allow(clippy::result_large_err)]
fn body<T: serde::de::DeserializeOwned>(b: &Bytes) -> Result<T, Response> {
    if b.len() > 64 * 1024 {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, Json(json!({"hata": "Istek govdesi cok buyuk"}))).into_response());
    }
    serde_json::from_slice(b).map_err(|e| err(format!("Gecersiz JSON istegi: {e}")))
}

fn is_local(v: &str) -> bool {
    let h = v.trim_start_matches("http://").trim_start_matches("https://").split('/').next().unwrap_or("");
    let host = if h.starts_with('[') { h.split(']').next().map(|x| format!("{x}]")).unwrap_or_default() } else { h.split(':').next().unwrap_or("").to_string() };
    matches!(host.as_str(), "127.0.0.1" | "localhost" | "[::1]" | "osint.ozanozdil.com" | "ozanozdil.com")
}

fn is_local_request(h: &axum::http::HeaderMap) -> bool {
    let get = |n: header::HeaderName| h.get(n).and_then(|v| v.to_str().ok());
    get(header::HOST).is_some_and(is_local) && get(header::ORIGIN).is_none_or(is_local)
}

/// DNS rebinding ve CSRF korumasi: Host yerel olmali, Origin varsa yerel olmali.
async fn guard(req: Request, next: Next) -> Response {
    if !is_local_request(req.headers()) {
        return (StatusCode::FORBIDDEN, Json(json!({"hata": "Yalnizca yerel erisime izin verilir"}))).into_response();
    }
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    h.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    h.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    h.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    h.insert(header::CONTENT_SECURITY_POLICY, "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'".parse().unwrap());
    r
}

#[derive(Deserialize)]
struct RunReq {
    modul: String,
    hedef: String,
    vaka: Option<i64>,
}

async fn run(State(a): S, b: Bytes) -> Response {
    let r: RunReq = match body(&b) { Ok(r) => r, Err(e) => return e };
    if r.modul == "media" {
        return err("Medya modulu guvenlik nedeniyle yalnizca CLI uzerinden kullanilabilir");
    }
    match modules::dispatch(&a.http, &a.cfg, &r.modul, &r.hedef).await {
        Ok(v) => save_and_reply(&a, r.vaka, &r.modul, &r.hedef, v),
        Err(e) => err(e),
    }
}

fn save_and_reply(a: &App, case: Option<i64>, module: &str, target: &str, v: Value) -> Response {
    if let Some(c) = case {
        if let Err(e) = lock(a).add_finding(c, module, target, &v) {
            return err(e);
        }
    }
    Json(v).into_response()
}

#[derive(Deserialize)]
struct PivotReq {
    tur: String,
    hedef: String,
    derinlik: Option<u32>,
    max_dugum: Option<usize>,
    genis: Option<bool>,
    vaka: Option<i64>,
}

async fn pivot_run(State(a): S, b: Bytes) -> Response {
    let r: PivotReq = match body(&b) { Ok(r) => r, Err(e) => return e };
    let Some(k) = pivot::Kind::parse(&r.tur) else { return err("Gecersiz tohum turu") };
    let opts = pivot::Options {
        max_depth: r.derinlik.unwrap_or(2).min(4),
        max_nodes: r.max_dugum.unwrap_or(150).min(500),
        wide: r.genis.unwrap_or(false),
        ..Default::default()
    };
    let mut eng = pivot::Engine::new(&a.http, &a.cfg, opts);
    let g = eng.run(k, &r.hedef, |_| {}).await;
    let analiz = correlate::analyze(g);
    let v = json!({"grafik": g, "analiz": analiz});
    save_and_reply(&a, r.vaka, "pivot", &r.hedef, v)
}

#[derive(Deserialize)]
struct CaseReq {
    ad: String,
    not: Option<String>,
}

async fn cases(State(a): S) -> Response {
    lock(&a).list_cases().map(|v| Json(v).into_response()).unwrap_or_else(err)
}

async fn case_new(State(a): S, b: Bytes) -> Response {
    let r: CaseReq = match body(&b) { Ok(r) => r, Err(e) => return e };
    if r.ad.trim().is_empty() || r.ad.len() > 200 {
        return err("Vaka adi 1-200 karakter olmali");
    }
    lock(&a).create_case(r.ad.trim(), r.not.as_deref().unwrap_or("")).map(|id| Json(json!({"id": id})).into_response()).unwrap_or_else(err)
}

async fn case_del(State(a): S, Path(id): Path<i64>) -> Response {
    match lock(&a).delete_case(id) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => err("no rows"),
        Err(e) => err(e),
    }
}

#[derive(Deserialize)]
struct Fmt {
    bicim: Option<String>,
}

async fn case_report(State(a): S, Path(id): Path<i64>, Query(f): Query<Fmt>) -> Response {
    let c = match lock(&a).case(id) {
        Ok(c) => c,
        Err(e) => return err(e),
    };
    match f.bicim.as_deref().unwrap_or("json") {
        "md" => ([(header::CONTENT_TYPE, "text/markdown; charset=utf-8")], report::markdown(&c)).into_response(),
        "html" => Html(report::html(&c)).into_response(),
        _ => Json(c).into_response(),
    }
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

pub async fn serve(host: Option<String>, port: u16) -> anyhow::Result<()> {
    let app = Arc::new(App { http: Http::new()?, cfg: Config::load(), store: Mutex::new(Store::open()?) });
    let router = Router::new()
        .route("/", get(index))
        .route("/api/calistir", post(run))
        .route("/api/pivot", post(pivot_run))
        .route("/api/vakalar", get(cases).post(case_new))
        .route("/api/vakalar/:id", delete(case_del))
        .route("/api/vakalar/:id/rapor", get(case_report))
        .layer(middleware::from_fn(guard))
        .with_state(app);
    let h = host.as_deref().unwrap_or("127.0.0.1");
    let ip: std::net::IpAddr = h.parse()?;
    let addr = std::net::SocketAddr::from((ip, port));
    println!("Web paneli acik: http://{addr}");
    let l = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(l, router).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn locality() {
        assert!(super::is_local("127.0.0.1:8787"));
        assert!(super::is_local("http://localhost:8787"));
        assert!(super::is_local("[::1]:8787"));
        assert!(super::is_local("osint.ozanozdil.com"));
        assert!(super::is_local("https://osint.ozanozdil.com:443"));
        assert!(!super::is_local("evil.com"));
        assert!(!super::is_local("https://127.0.0.1.evil.com"));
        assert!(!super::is_local("http://localhost.evil.com:8787"));
    }
}
