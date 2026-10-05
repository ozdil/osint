//! Yerel web paneli (yalnizca 127.0.0.1).

use crate::{config::Config, correlate, http::Http, modules, pivot, report, store::Store};
use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
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
    (StatusCode::BAD_REQUEST, Json(json!({"hata": e.to_string()}))).into_response()
}

#[derive(Deserialize)]
struct RunReq {
    modul: String,
    hedef: String,
    vaka: Option<i64>,
}

async fn run(State(a): S, Json(r): Json<RunReq>) -> Response {
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
        if let Err(e) = a.store.lock().unwrap().add_finding(c, module, target, &v) {
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

async fn pivot_run(State(a): S, Json(r): Json<PivotReq>) -> Response {
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
    a.store.lock().unwrap().list_cases().map(|v| Json(v).into_response()).unwrap_or_else(err)
}

async fn case_new(State(a): S, Json(r): Json<CaseReq>) -> Response {
    if r.ad.trim().is_empty() || r.ad.len() > 200 {
        return err("Vaka adi 1-200 karakter olmali");
    }
    a.store.lock().unwrap().create_case(r.ad.trim(), r.not.as_deref().unwrap_or("")).map(|id| Json(json!({"id": id})).into_response()).unwrap_or_else(err)
}

async fn case_del(State(a): S, Path(id): Path<i64>) -> Response {
    a.store.lock().unwrap().delete_case(id).map(|_| StatusCode::NO_CONTENT.into_response()).unwrap_or_else(err)
}

#[derive(Deserialize)]
struct Fmt {
    bicim: Option<String>,
}

async fn case_report(State(a): S, Path(id): Path<i64>, Query(f): Query<Fmt>) -> Response {
    let c = match a.store.lock().unwrap().case(id) {
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

pub async fn serve(port: u16) -> anyhow::Result<()> {
    let app = Arc::new(App { http: Http::new()?, cfg: Config::load(), store: Mutex::new(Store::open()?) });
    let router = Router::new()
        .route("/", get(index))
        .route("/api/calistir", post(run))
        .route("/api/pivot", post(pivot_run))
        .route("/api/vakalar", get(cases).post(case_new))
        .route("/api/vakalar/:id", delete(case_del))
        .route("/api/vakalar/:id/rapor", get(case_report))
        .with_state(app);
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    println!("Web paneli: http://{addr}");
    let l = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(l, router).await?;
    Ok(())
}
