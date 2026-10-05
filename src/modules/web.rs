//! Web istihbarati: baslik analizi, teknoloji parmak izi, takip kimlikleri, favicon hash,
//! robots/security.txt, Wayback arsivi.

use crate::{http::Http, validate};
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::BTreeSet;

const SIGNATURES: &[(&str, &str)] = &[
    ("wp-content", "WordPress"),
    ("Joomla!", "Joomla"),
    ("Drupal.settings", "Drupal"),
    ("cdn.shopify.com", "Shopify"),
    ("__NEXT_DATA__", "Next.js"),
    ("__NUXT__", "Nuxt"),
    ("data-reactroot", "React"),
    ("ng-version", "Angular"),
    ("data-v-", "Vue"),
    ("laravel_session", "Laravel"),
    ("csrfmiddlewaretoken", "Django"),
    ("jquery", "jQuery"),
    ("bootstrap", "Bootstrap"),
    ("cloudflare", "Cloudflare"),
    ("recaptcha", "reCAPTCHA"),
];

const SECURITY_HEADERS: &[&str] = &[
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
];

/// Sayfa kaynagindan takip/analitik kimliklerini cikarir (iliskilendirme icin kritik).
pub fn tracking_ids(body: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    let prefixes: &[(&str, usize, bool)] = &[
        ("UA-", 6, true),
        ("G-", 8, false),
        ("GTM-", 5, false),
        ("ca-pub-", 10, true),
        ("pub-", 10, true),
    ];
    for (p, min, digits_only) in prefixes {
        let mut rest = body;
        while let Some(i) = rest.find(p) {
            let before_ok = i == 0 || !rest.as_bytes()[i - 1].is_ascii_alphanumeric();
            let tail = &rest[i + p.len()..];
            let id: String = tail
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || (*digits_only && *c == '-'))
                .collect();
            let valid = if *digits_only {
                id.chars().all(|c| c.is_ascii_digit() || c == '-') && id.len() >= *min
            } else {
                id.len() >= *min && id.len() <= 12 && id.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            };
            if before_ok && valid {
                let norm = if *p == "pub-" { format!("ca-pub-{id}") } else { format!("{p}{id}") };
                out.insert(norm.trim_end_matches('-').to_string());
            }
            rest = &rest[i + p.len()..];
        }
    }
    out.into_iter().collect()
}

pub fn emails_in(body: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    for tok in body.split(|c: char| !(c.is_ascii_alphanumeric() || "@._%+-".contains(c))) {
        if tok.matches('@').count() == 1 {
            if let Ok((l, d)) = validate::email(tok.trim_matches('.')) {
                let tld = d.rsplit('.').next().unwrap_or("");
                if tld.chars().all(|c| c.is_ascii_alphabetic()) && !["png", "jpg", "gif", "svg", "webp"].contains(&tld) {
                    out.insert(format!("{l}@{d}"));
                }
            }
        }
    }
    out.into_iter().collect()
}

pub fn title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let s = lower.find("<title")?;
    let s = s + lower[s..].find('>')? + 1;
    let e = s + lower[s..].find("</title")?;
    Some(body.get(s..e)?.trim().chars().take(200).collect())
}

/// Shodan uyumlu favicon hash: base64 (76 karakter satir) uzerinde MurmurHash3 x86_32.
pub fn favicon_hash(bytes: &[u8]) -> i32 {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for c in bytes.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        b64.push(T[(n >> 18) as usize & 63] as char);
        b64.push(T[(n >> 12) as usize & 63] as char);
        b64.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        b64.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    let mut enc = String::new();
    for (i, ch) in b64.chars().enumerate() {
        enc.push(ch);
        if (i + 1) % 76 == 0 {
            enc.push('\n');
        }
    }
    if !enc.ends_with('\n') {
        enc.push('\n');
    }
    murmur3_32(enc.as_bytes(), 0) as i32
}

fn murmur3_32(data: &[u8], seed: u32) -> u32 {
    let (c1, c2) = (0xcc9e2d51u32, 0x1b873593u32);
    let mut h = seed;
    let (chunks, tail) = data.as_chunks::<4>();
    for c in chunks {
        let mut k = u32::from_le_bytes(*c);
        k = k.wrapping_mul(c1).rotate_left(15).wrapping_mul(c2);
        h ^= k;
        h = h.rotate_left(13).wrapping_mul(5).wrapping_add(0xe6546b64);
    }
    let mut k = 0u32;
    for (i, b) in tail.iter().enumerate() {
        k |= (*b as u32) << (8 * i);
    }
    if !tail.is_empty() {
        h ^= k.wrapping_mul(c1).rotate_left(15).wrapping_mul(c2);
    }
    h ^= data.len() as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85ebca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2ae35);
    h ^ (h >> 16)
}

pub fn normalize_url(target: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!("https://{target}")
    }
}

pub async fn wayback(http: &Http, host: &str) -> Result<Value> {
    let url = format!(
        "https://web.archive.org/cdx/search/cdx?url={host}/*&output=json&fl=timestamp,original,statuscode,mimetype&collapse=urlkey&limit=200"
    );
    let v = http.json(&url, 2 * 1024 * 1024).await?;
    let rows: Vec<Value> = v.as_array().into_iter().flatten().skip(1).cloned().collect();
    let first = rows.iter().filter_map(|r| r[0].as_str()).min().map(str::to_string);
    let interesting: Vec<&Value> = rows
        .iter()
        .filter(|r| {
            let u = r[1].as_str().unwrap_or("").to_ascii_lowercase();
            [".env", ".sql", ".bak", ".zip", "admin", "config", "backup", ".git", "api/", ".json", ".xml", "wp-login"]
                .iter()
                .any(|k| u.contains(k))
        })
        .take(50)
        .collect();
    Ok(json!({"kayit_sayisi": rows.len(), "ilk_arsiv": first, "dikkat_ceken_urller": interesting}))
}

pub async fn run(http: &Http, target: &str) -> Result<Value> {
    let url = normalize_url(target.trim());
    let parsed = url::Url::parse(&url)?;
    let host = parsed.host_str().unwrap_or_default().to_string();
    let base = format!("{}://{}", parsed.scheme(), parsed.authority());

    let page = http.fetch_untrusted(&url).await?;
    let headers: serde_json::Map<String, Value> =
        page.headers.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
    let lower = page.body.to_ascii_lowercase();
    let mut tech: BTreeSet<String> = SIGNATURES
        .iter()
        .filter(|(k, _)| lower.contains(&k.to_ascii_lowercase()))
        .map(|(_, n)| n.to_string())
        .collect();
    for (k, v) in &page.headers {
        if k == "server" || k == "x-powered-by" {
            tech.insert(v.clone());
        }
    }
    let missing: Vec<&str> = SECURITY_HEADERS
        .iter()
        .filter(|h| !page.headers.iter().any(|(k, _)| k == *h))
        .copied()
        .collect();

    let (ru, su) = (format!("{base}/robots.txt"), format!("{base}/.well-known/security.txt"));
    let (robots, sec, fav, wb) = tokio::join!(
        http.fetch_untrusted(&ru),
        http.fetch_untrusted(&su),
        favicon(http, &base),
        wayback(http, &host),
    );
    let txt = |r: Result<crate::http::Fetched>| match r {
        Ok(f) if f.status == 200 && !f.body.trim_start().starts_with('<') => json!(f.body.chars().take(4000).collect::<String>()),
        _ => Value::Null,
    };
    let robots_v = txt(robots);
    let disallow: Vec<String> = robots_v
        .as_str()
        .unwrap_or("")
        .lines()
        .filter_map(|l| l.trim().strip_prefix("Disallow:").map(|p| p.trim().to_string()))
        .filter(|p| !p.is_empty() && p != "/")
        .collect();

    Ok(json!({
        "url": url,
        "host": host,
        "durum_kodu": page.status,
        "baslik": title(&page.body),
        "yonlendirme": page.headers.iter().find(|(k, _)| k == "location").map(|(_, v)| v),
        "teknolojiler": tech,
        "eksik_guvenlik_basliklari": missing,
        "takip_kimlikleri": tracking_ids(&page.body),
        "epostalar": emails_in(&page.body),
        "favicon_mmh3": fav.ok(),
        "robots_gizli_yollar": disallow,
        "security_txt": txt(sec),
        "wayback": wb.unwrap_or_else(|e| json!({"hata": e.to_string()})),
        "basliklar": headers,
    }))
}

async fn favicon(http: &Http, base: &str) -> Result<i32> {
    let raw = http.raw_untrusted(&format!("{base}/favicon.ico")).await?;
    anyhow::ensure!(!raw.is_empty(), "favicon yok");
    Ok(favicon_hash(&raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracking() {
        let b = r#"gtag('config','G-ABC123XYZ9'); UA-1234567-2 GTM-KX9P2Q data-ad-client="ca-pub-1234567890123456""#;
        let ids = tracking_ids(b);
        assert!(ids.contains(&"G-ABC123XYZ9".to_string()));
        assert!(ids.contains(&"UA-1234567-2".to_string()));
        assert!(ids.contains(&"GTM-KX9P2Q".to_string()));
        assert!(ids.contains(&"ca-pub-1234567890123456".to_string()));
    }

    #[test]
    fn emails() {
        let e = emails_in("iletisim: info@ornek.com.tr, logo@2x.png bilgi@ornek.com");
        assert_eq!(e, vec!["bilgi@ornek.com", "info@ornek.com.tr"]);
    }

    #[test]
    fn mmh3() {
        assert_eq!(murmur3_32(b"", 0), 0);
        assert_eq!(murmur3_32(b"hello", 0), 0x248bfa47);
    }

    #[test]
    fn titles() {
        assert_eq!(title("<html><TITLE>Merhaba</title>").as_deref(), Some("Merhaba"));
    }
}
