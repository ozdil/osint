//! Faz 3: Gecmis ve sizinti izleri.
//! - Sertifika gecmisi (crt.sh): ihrac zaman cizelgesi ve saglayicilar
//! - Wayback: uc nokta / parametre / dosya uzantisi envanteri, arsivlenmis sayfalardan e-posta
//! - GitHub kod aramasi: alan adinin hassas baglamda gectigi depolar (yalnizca konum; icerik cekilmez)

use crate::{config::Config, http::Http, modules::web::emails_in, validate};
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub async fn cert_history(http: &Http, d: &str) -> Result<Value> {
    let mut issuers: BTreeMap<String, usize> = BTreeMap::new();
    let mut years: BTreeMap<String, usize> = BTreeMap::new();
    let mut first: Option<String> = None;
    let mut total_count = 0usize;
    let mut source = "crt.sh";

    // 1. Birincil CT Log Kaynagi: crt.sh
    let crt_res = http.json(&format!("https://crt.sh/?q={d}&output=json"), 8 * 1024 * 1024).await;
    if let Ok(v) = crt_res {
        let rows = v.as_array().cloned().unwrap_or_default();
        total_count = rows.len();
        for r in &rows {
            let iss = r["issuer_name"].as_str().unwrap_or("");
            let org = iss.split(',').find_map(|p| p.trim().strip_prefix("O=")).unwrap_or(iss).trim_matches('"').to_string();
            if !org.is_empty() {
                *issuers.entry(org).or_default() += 1;
            }
            if let Some(nb) = r["not_before"].as_str() {
                *years.entry(nb.chars().take(4).collect()).or_default() += 1;
                if first.as_deref().is_none_or(|f| nb < f) {
                    first = Some(nb.to_string());
                }
            }
        }
    } else {
        // 2. Yedek CT Log Kaynagi: CertSpotter
        source = "certspotter";
        let cs_res = http.json(&format!("https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names"), 4 * 1024 * 1024).await;
        if let Ok(v) = cs_res {
            let rows = v.as_array().cloned().unwrap_or_default();
            total_count = rows.len();
            for r in &rows {
                if let Some(nb) = r["not_before"].as_str() {
                    *years.entry(nb.chars().take(4).collect()).or_default() += 1;
                    if first.as_deref().is_none_or(|f| nb < f) {
                        first = Some(nb.to_string());
                    }
                }
            }
        }
    }

    Ok(json!({
        "kaynak": source,
        "sertifika_sayisi": total_count,
        "ilk_sertifika": first,
        "saglayicilar": issuers,
        "yillara_gore": years
    }))
}

/// Arsivlenmis URL listesinden uc nokta envanteri cikarir.
pub fn endpoint_inventory(urls: &[String]) -> Value {
    let mut paths = BTreeSet::new();
    let mut params: BTreeMap<String, usize> = BTreeMap::new();
    let mut exts: BTreeMap<String, usize> = BTreeMap::new();
    let mut subs = BTreeSet::new();
    for u in urls {
        let Ok(p) = url::Url::parse(u) else { continue };
        if let Some(h) = p.host_str() {
            subs.insert(h.trim_start_matches("www.").to_string());
        }
        let path = p.path().to_string();
        if let Some(e) = path.rsplit('/').next().and_then(|f| f.rsplit_once('.')).map(|(_, e)| e.to_ascii_lowercase()) {
            if e.len() <= 5 && e.chars().all(|c| c.is_ascii_alphanumeric()) {
                *exts.entry(e).or_default() += 1;
            }
        }
        for (k, _) in p.query_pairs() {
            *params.entry(k.into_owned()).or_default() += 1;
        }
        if paths.len() < 500 {
            paths.insert(path);
        }
    }
    let sensitive: Vec<&String> = paths
        .iter()
        .filter(|p| {
            let l = p.to_ascii_lowercase();
            ["admin", "login", "api", "graphql", "swagger", "backup", ".env", ".git", "config", "debug", "phpinfo", "upload", ".sql", ".bak", "wp-json", "actuator", "console"]
                .iter()
                .any(|k| l.contains(k))
        })
        .take(100)
        .collect();
    json!({
        "benzersiz_yol": paths.len(),
        "hassas_yollar": sensitive,
        "parametreler": params,
        "uzantilar": exts,
        "arsivdeki_hostlar": subs,
    })
}

pub async fn wayback_deep(http: &Http, d: &str) -> Result<Value> {
    let url = format!("https://web.archive.org/cdx/search/cdx?url=*.{d}/*&output=json&fl=original&collapse=urlkey&limit=5000");
    let v = http.json(&url, 8 * 1024 * 1024).await?;
    let urls: Vec<String> = v.as_array().into_iter().flatten().skip(1).filter_map(|r| r[0].as_str().map(str::to_string)).collect();
    let inv = endpoint_inventory(&urls);

    // Ana sayfanin farkli yillardaki arsiv kopyalarindan e-posta toplama (en fazla 6 kopya)
    let snaps = http
        .json(&format!("https://web.archive.org/cdx/search/cdx?url={d}&output=json&fl=timestamp&collapse=timestamp:4&filter=statuscode:200&limit=6"), 64 * 1024)
        .await
        .unwrap_or(Value::Null);
    let mut emails = BTreeSet::new();
    let mut checked = vec![];
    for ts in snaps.as_array().into_iter().flatten().skip(1).filter_map(|r| r[0].as_str()) {
        if let Ok(body) = http.text(&format!("https://web.archive.org/web/{ts}id_/https://{d}/"), 1024 * 1024).await {
            emails.extend(emails_in(&body));
            checked.push(ts.to_string());
        }
    }
    Ok(json!({"arsiv_url_sayisi": urls.len(), "envanter": inv, "incelenen_kopyalar": checked, "gecmis_epostalar": emails}))
}

pub async fn github_exposure(http: &Http, cfg: &Config, d: &str) -> Value {
    let Some(tok) = &cfg.github_token else {
        return json!({"durum": "GitHub token tanimli degil (osint config set github_token ...)",
                      "manuel_arama": format!("https://github.com/search?type=code&q=%22{d}%22+password")});
    };
    let auth = format!("Bearer {tok}");
    let terms = ["password", "secret", "api_key", "token", "smtp", "BEGIN RSA PRIVATE KEY"];
    let mut hits = vec![];
    for t in terms {
        let q = format!("%22{d}%22+%22{}%22", t.replace(' ', "+"));
        let r = http
            .json_with(
                &format!("https://api.github.com/search/code?q={q}&per_page=20"),
                2 * 1024 * 1024,
                &[("authorization", &auth), ("accept", "application/vnd.github+json"), ("x-github-api-version", "2022-11-28")],
            )
            .await;
        match r {
            Ok(v) => {
                for it in v["items"].as_array().into_iter().flatten() {
                    hits.push(json!({"terim": t, "depo": it["repository"]["full_name"], "dosya": it["path"], "url": it["html_url"]}));
                }
            }
            Err(e) => {
                hits.push(json!({"terim": t, "hata": e.to_string()}));
                break; // hiz siniri: kalan terimleri atla
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    }
    let repos: BTreeSet<String> = hits.iter().filter_map(|h| h["depo"].as_str().map(str::to_string)).collect();
    json!({"eslesme": hits.len(), "depolar": repos, "bulgular": hits,
           "not": "Yalnizca konum raporlanir; dosya icerigi cekilmez. Bulgular sorumlu bildirim icin kullanilmalidir."})
}

pub async fn run(http: &Http, cfg: &Config, target: &str) -> Result<Value> {
    let d = validate::domain(target)?;
    let (c, w, g) = tokio::join!(cert_history(http, &d), wayback_deep(http, &d), github_exposure(http, cfg, &d));
    let e = |r: Result<Value>| r.unwrap_or_else(|e| json!({"hata": e.to_string()}));
    Ok(json!({"alan_adi": d, "sertifika_gecmisi": e(c), "wayback": e(w), "github": g}))
}

#[cfg(test)]
mod tests {
    #[test]
    fn inventory() {
        let u = vec![
            "https://www.a.com/api/v1/users?id=1&token=x".to_string(),
            "https://a.com/backup.sql".to_string(),
            "https://dev.a.com/index.php?page=2".to_string(),
        ];
        let v = super::endpoint_inventory(&u);
        assert_eq!(v["parametreler"]["id"], 1);
        assert_eq!(v["uzantilar"]["sql"], 1);
        assert_eq!(v["hassas_yollar"].as_array().unwrap().len(), 2);
        assert!(v["arsivdeki_hostlar"].as_array().unwrap().iter().any(|h| h == "dev.a.com"));
    }
}
