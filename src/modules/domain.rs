//! Alan adi istihbarati: DNS (DoH), RDAP, sertifika seffafligi, e-posta guvenligi.

use crate::{http::Http, validate};
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::BTreeSet;

const RECORD_TYPES: &[&str] = &["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "CNAME"];

static RESOLVER: std::sync::OnceLock<Option<hickory_resolver::TokioAsyncResolver>> = std::sync::OnceLock::new();

/// Birincil: sistem cozumleyicisi (UDP/TCP 53). Yedek: DNS-over-HTTPS.
pub async fn dns(http: &Http, name: &str, rtype: &str) -> Result<Vec<String>> {
    use hickory_resolver::proto::rr::RecordType;
    let r = RESOLVER.get_or_init(|| hickory_resolver::TokioAsyncResolver::tokio_from_system_conf().ok());
    if let (Some(r), Ok(rt)) = (r, rtype.parse::<RecordType>()) {
        match r.lookup(name, rt).await {
            Ok(l) => {
                return Ok(l
                    .record_iter()
                    .filter(|rec| rec.record_type() == rt)
                    .filter_map(|rec| rec.data().map(|d| d.to_string().trim_matches('"').to_string()))
                    .collect())
            }
            Err(e) if matches!(e.kind(), hickory_resolver::error::ResolveErrorKind::NoRecordsFound { .. }) => return Ok(vec![]),
            Err(_) => {}
        }
    }
    let url = format!("https://cloudflare-dns.com/dns-query?name={name}&type={rtype}");
    let v = http
        .json_with(&url, 256 * 1024, &[("accept", "application/dns-json")])
        .await?;
    Ok(v["Answer"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|r| r["data"].as_str())
                .map(|s| s.trim_matches('"').to_string())
                .collect()
        })
        .unwrap_or_default())
}

pub async fn records(http: &Http, d: &str) -> Value {
    let futs = RECORD_TYPES.iter().map(|t| async move { (*t, dns(http, d, t).await) });
    let mut out = serde_json::Map::new();
    for (t, r) in futures::future::join_all(futs).await {
        out.insert(t.into(), r.map(|v| json!(v)).unwrap_or_else(|e| json!({"hata": e.to_string()})));
    }
    Value::Object(out)
}

pub async fn rdap(http: &Http, d: &str) -> Result<Value> {
    let v = http.json(&format!("https://rdap.org/domain/{d}"), MAX_RDAP).await?;
    if v.is_null() {
        return Ok(json!({"durum": "kayit bulunamadi"}));
    }
    let events: Vec<Value> = v["events"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|e| json!({"olay": e["eventAction"], "tarih": e["eventDate"]}))
        .collect();
    let registrar = v["entities"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|e| e["roles"].as_array().is_some_and(|r| r.iter().any(|x| x == "registrar")))
        .and_then(|e| e["vcardArray"][1].as_array())
        .and_then(|card| card.iter().find(|f| f[0] == "fn"))
        .map(|f| f[3].clone())
        .unwrap_or(Value::Null);
    let ns: Vec<Value> = v["nameservers"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|n| n["ldhName"].clone())
        .collect();
    Ok(json!({
        "kayit_firmasi": registrar,
        "durum": v["status"],
        "olaylar": events,
        "ad_sunuculari": ns,
    }))
}
const MAX_RDAP: usize = 512 * 1024;

/// crt.sh ve CertSpotter uzerinden alt alan adlari (Cift kaynakli CT Log arastirmasi).
pub async fn subdomains(http: &Http, d: &str) -> Result<Vec<String>> {
    let suffix = format!(".{d}");
    let mut set = BTreeSet::new();

    // 1. Kaynak: crt.sh
    let crt_url = format!("https://crt.sh/?q=%25.{d}&output=json");
    if let Ok(v) = http.json(&crt_url, 8 * 1024 * 1024).await {
        for row in v.as_array().into_iter().flatten() {
            if let Some(names) = row["name_value"].as_str() {
                for n in names.lines() {
                    let n = n.trim().trim_start_matches("*.").to_ascii_lowercase();
                    if n == d || n.ends_with(&suffix) {
                        set.insert(n);
                    }
                }
            }
        }
    }

    // 2. Kaynak: CertSpotter (crt.sh genelde 502/rate-limit donerse kurtarici kaynak)
    let cs_url = format!("https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names");
    if let Ok(v) = http.json(&cs_url, 4 * 1024 * 1024).await {
        for item in v.as_array().into_iter().flatten() {
            for dns_name in item["dns_names"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                let n = dns_name.trim().trim_start_matches("*.").to_ascii_lowercase();
                if n == d || n.ends_with(&suffix) {
                    set.insert(n);
                }
            }
        }
    }

    if set.is_empty() {
        // En azindan ana alan adini ve www varyasyonunu temel olarak donelim
        set.insert(d.to_string());
    }

    Ok(set.into_iter().collect())
}

pub async fn email_security(http: &Http, d: &str) -> Value {
    let txt = dns(http, d, "TXT").await.unwrap_or_default();
    let spf: Vec<_> = txt.iter().filter(|t| t.starts_with("v=spf1")).cloned().collect();
    let dmarc: Vec<_> = dns(http, &format!("_dmarc.{d}"), "TXT")
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|t| t.starts_with("v=DMARC1"))
        .collect();
    let mut dkim = Vec::new();
    for sel in ["default", "google", "selector1", "selector2", "k1", "mail", "dkim"] {
        if let Ok(r) = dns(http, &format!("{sel}._domainkey.{d}"), "TXT").await {
            if r.iter().any(|t| t.contains("v=DKIM1") || t.contains("k=rsa") || t.contains("k=ed25519")) {
                dkim.push(sel);
            }
        }
    }
    let policy = dmarc
        .first()
        .and_then(|r| r.split(';').find_map(|p| p.trim().strip_prefix("p=").map(str::to_string)));
    json!({
        "spf": spf,
        "spf_var": !spf.is_empty(),
        "dmarc": dmarc,
        "dmarc_politikasi": policy,
        "dkim_seciciler": dkim,
        "degerlendirme": match (spf.is_empty(), policy.as_deref()) {
            (false, Some("reject")) | (false, Some("quarantine")) => "guclu",
            (false, _) => "orta (DMARC zayif veya yok)",
            _ => "zayif (SPF yok, sahtecilige acik)",
        }
    })
}

pub async fn run(http: &Http, target: &str) -> Result<Value> {
    let d = validate::domain(target)?;
    let (rec, whois, subs, mail) = tokio::join!(
        records(http, &d),
        rdap(http, &d),
        subdomains(http, &d),
        email_security(http, &d)
    );
    let subs_v = match subs {
        Ok(s) => json!({"adet": s.len(), "liste": s}),
        Err(e) => json!({"hata": e.to_string()}),
    };
    Ok(json!({
        "alan_adi": d,
        "dns": rec,
        "rdap": whois.unwrap_or_else(|e| json!({"hata": e.to_string()})),
        "alt_alan_adlari": subs_v,
        "eposta_guvenligi": mail,
    }))
}
