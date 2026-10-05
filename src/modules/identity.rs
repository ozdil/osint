//! Kimlik istihbarati: kullanici adi platform taramasi, e-posta, telefon.

use crate::{config::Config, http::Http, modules::domain::dns, validate};
use anyhow::Result;
use futures::{stream, StreamExt};
use md5::{Digest, Md5};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize, serde::Serialize, Clone)]
struct Site {
    ad: String,
    url: String,
    kontrol: String,
    #[serde(default)]
    yok: String,
    /// WhatsMyName: hesap varsa beklenen durum kodu ve metin
    #[serde(default, skip_serializing_if = "Option::is_none")]
    var_kod: Option<u16>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    var_metin: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    kategori: String,
}

const WMN_URL: &str = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json";
const MAX_SITES_FILE: u64 = 8 * 1024 * 1024;

/// WhatsMyName veritabanini indirir, donusturur ve ~/.config/osint/sites.json'a atomik yazar.
pub async fn update_db(http: &Http) -> Result<usize> {
    let v = http.json(WMN_URL, MAX_SITES_FILE as usize).await?;
    let builtin: std::collections::HashSet<String> = sites_builtin().into_iter().map(|s| s.ad.to_lowercase()).collect();
    let mut out = vec![];
    for x in v["sites"].as_array().into_iter().flatten() {
        let (Some(name), Some(uri)) = (x["name"].as_str(), x["uri_check"].as_str()) else { continue };
        if x["valid"] == false || x["post_body"].is_string() || builtin.contains(&name.to_lowercase()) {
            continue;
        }
        if !uri.starts_with("https://") && !uri.starts_with("http://") {
            continue;
        }
        out.push(Site {
            ad: name.to_string(),
            url: uri.replace("{account}", "{}"),
            kontrol: "wmn".into(),
            yok: x["m_string"].as_str().unwrap_or("").to_string(),
            var_kod: x["e_code"].as_u64().map(|c| c as u16),
            var_metin: x["e_string"].as_str().unwrap_or("").to_string(),
            kategori: x["cat"].as_str().unwrap_or("").to_string(),
        });
    }
    let path = crate::config::config_dir()?.join("sites.json");
    crate::config::write_atomic(&path, serde_json::to_string(&out)?.as_bytes())?;
    Ok(out.len())
}

fn sites_builtin() -> Vec<Site> {
    serde_json::from_str(include_str!("../../data/sites.json")).unwrap_or_default()
}

/// Profil sayfasindan diger platformlara verilen baglantilari ve e-postalari cikarir.
pub fn linked_accounts(body: &str, own_host: &str) -> Vec<String> {
    const SOCIAL: &[&str] = &[
        "github.com", "gitlab.com", "twitter.com", "x.com", "instagram.com", "linkedin.com/in", "facebook.com",
        "youtube.com/@", "youtube.com/c/", "t.me", "reddit.com/user", "medium.com/@", "mastodon.social/@",
        "bsky.app/profile", "tiktok.com/@", "twitch.tv", "keybase.io", "linktr.ee", "about.me",
    ];
    let mut out = std::collections::BTreeSet::new();
    let mut rest = body;
    while let Some(i) = rest.find("http") {
        rest = &rest[i..];
        let end = rest.find(|c: char| c.is_whitespace() || "\"'<>)\\".contains(c)).unwrap_or(rest.len());
        let link = &rest[..end.min(300)];
        rest = &rest[end.max(4)..];
        let Ok(u) = url::Url::parse(link) else { continue };
        let Some(h) = u.host_str() else { continue };
        let h = h.trim_start_matches("www.");
        if h == own_host || own_host.ends_with(h) {
            continue;
        }
        let hp = format!("{h}{}", u.path());
        if u.path().len() > 1 && SOCIAL.iter().any(|s| hp.starts_with(s)) {
            out.insert(format!("https://{}", hp.trim_end_matches('/')));
        }
        if out.len() >= 25 {
            break;
        }
    }
    out.into_iter().collect()
}

fn sites() -> Vec<Site> {
    let mut s = sites_builtin();
    // Kullanici tanimli ek imzalar: ~/.config/osint/sites.json
    if let Some(p) = dirs::config_dir().map(|d| d.join("osint/sites.json")) {
        if let Ok(txt) = crate::config::read_limited(&p, MAX_SITES_FILE) {
            if let Ok(extra) = serde_json::from_str::<Vec<Site>>(&txt) {
                s.extend(extra);
            }
        }
    }
    s
}

pub async fn username(http: &Http, target: &str) -> Result<Value> {
    let u = validate::username(target)?;
    let all = sites();
    let total = all.len();
    let results: Vec<Value> = stream::iter(all)
        .map(|s| {
            let u = u.clone();
            async move {
                let url = s.url.replace("{}", &u);
                let r = http.probe(&url).await;
                let found = match &r {
                    Ok(f) if s.kontrol == "wmn" => {
                        s.var_kod.is_none_or(|c| c == f.status)
                            && (s.var_metin.is_empty() || f.body.contains(&s.var_metin))
                            && (s.yok.is_empty() || !f.body.contains(&s.yok))
                    }
                    Ok(f) if s.kontrol == "metin_yok" => f.status == 200 && !f.body.contains(&s.yok),
                    Ok(f) => f.status == 200,
                    Err(_) => false,
                };
                let f = r.ok().filter(|_| found)?;
                let host = url::Url::parse(&url).ok().and_then(|u| u.host_str().map(|h| h.trim_start_matches("www.").to_string())).unwrap_or_default();
                Some(json!({
                    "platform": s.ad,
                    "kategori": s.kategori,
                    "url": url.replace("/about.json", "").replace(".json", ""),
                    // Platform altbilgi baglantilarini elemek icin yalnizca kullanici adini iceren baglantilar
                    "baglantili_hesaplar": linked_accounts(&f.body, &host).into_iter().filter(|l| l.to_lowercase().contains(&u.to_lowercase())).collect::<Vec<_>>(),
                    "epostalar": crate::modules::web::emails_in(&f.body),
                }))
            }
        })
        .buffer_unordered(24)
        .filter_map(|x| async { x })
        .collect()
        .await;
    let mut results = results;
    let mut linked = std::collections::BTreeSet::new();
    for r in &results {
        for l in r["baglantili_hesaplar"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            linked.insert(l.to_string());
        }
    }
    results.sort_by(|a, b| a["platform"].as_str().cmp(&b["platform"].as_str()));
    Ok(json!({
        "kullanici_adi": u,
        "taranan_platform": total,
        "bulunan": results.len(),
        "hesaplar": results,
        "capraz_baglantilar": linked,
        "varyasyon_onerileri": variations(&u),
    }))
}

fn variations(u: &str) -> Vec<String> {
    let base = u.replace(['.', '_', '-'], "");
    let mut v = vec![base.clone(), format!("{base}_"), format!("_{base}"), format!("{base}1"), format!("the{base}"), format!("{base}official")];
    if u.contains(['.', '_', '-']) {
        v.push(u.replace(['.', '-'], "_"));
        v.push(u.replace(['_', '-'], "."));
    }
    v.retain(|x| x != u);
    v.dedup();
    v
}

pub async fn email(http: &Http, cfg: &Config, target: &str) -> Result<Value> {
    let (local, domain) = validate::email(target)?;
    let addr = format!("{local}@{domain}");
    let hash = hex::encode(Md5::digest(addr.as_bytes()));
    let gurl = format!("https://en.gravatar.com/{hash}.json");
    let (mx, grav) = tokio::join!(
        dns(http, &domain, "MX"),
        http.json(&gurl, 256 * 1024)
    );
    let mx = mx.unwrap_or_default();
    let free = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com", "yandex.com", "proton.me", "protonmail.com", "gmx.com", "mail.ru", "aol.com"];
    let disposable = ["mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "yopmail.com", "trashmail.com"];
    let gravatar = match grav {
        Ok(v) if !v.is_null() => {
            let e = &v["entry"][0];
            json!({"var": true, "profil": e["profileUrl"], "ad": e["displayName"], "konum": e["currentLocation"], "hesaplar": e["accounts"]})
        }
        _ => json!({"var": false}),
    };
    let breaches = match &cfg.hibp_key {
        Some(k) => http
            .json_with(
                &format!("https://haveibeenpwned.com/api/v3/breachedaccount/{addr}?truncateResponse=false"),
                1024 * 1024,
                &[("hibp-api-key", k.as_str())],
            )
            .await
            .map(|v| {
                if v.is_null() {
                    json!({"durum": "ihlal kaydi yok"})
                } else {
                    json!(v.as_array().into_iter().flatten().map(|b| json!({"ad": b["Name"], "tarih": b["BreachDate"], "veri": b["DataClasses"]})).collect::<Vec<_>>())
                }
            })
            .unwrap_or_else(|e| json!({"hata": e.to_string()})),
        None => json!({"durum": "HIBP anahtari tanimli degil (osint config set hibp_key ...)"}),
    };
    Ok(json!({
        "eposta": addr,
        "alan_adi": domain,
        "mx": mx,
        "teslim_edilebilir_alan": !mx.is_empty(),
        "ucretsiz_saglayici": free.contains(&domain.as_str()),
        "gecici_eposta": disposable.contains(&domain.as_str()),
        "gravatar_md5": hash,
        "gravatar": gravatar,
        "ihlaller": breaches,
        "kullanici_adi_adayi": local.split('+').next(),
    }))
}

const COUNTRY_CODES: &[(&str, &str)] = &[
    ("1", "ABD/Kanada"), ("7", "Rusya/Kazakistan"), ("20", "Misir"), ("27", "Guney Afrika"),
    ("30", "Yunanistan"), ("31", "Hollanda"), ("32", "Belcika"), ("33", "Fransa"), ("34", "Ispanya"),
    ("36", "Macaristan"), ("39", "Italya"), ("40", "Romanya"), ("41", "Isvicre"), ("43", "Avusturya"),
    ("44", "Birlesik Krallik"), ("45", "Danimarka"), ("46", "Isvec"), ("47", "Norvec"), ("48", "Polonya"),
    ("49", "Almanya"), ("52", "Meksika"), ("55", "Brezilya"), ("61", "Avustralya"), ("62", "Endonezya"),
    ("81", "Japonya"), ("82", "Guney Kore"), ("86", "Cin"), ("90", "Turkiye"), ("91", "Hindistan"),
    ("92", "Pakistan"), ("98", "Iran"), ("355", "Arnavutluk"), ("359", "Bulgaristan"), ("380", "Ukrayna"),
    ("964", "Irak"), ("966", "Suudi Arabistan"), ("971", "BAE"), ("972", "Israil"), ("994", "Azerbaycan"),
    ("995", "Gurcistan"), ("993", "Turkmenistan"), ("996", "Kirgizistan"), ("998", "Ozbekistan"),
];

pub fn phone(target: &str) -> Result<Value> {
    let p = validate::phone(target)?;
    let digits = &p[1..];
    let (cc, country) = (1..=3)
        .rev()
        .filter_map(|n| digits.get(..n))
        .find_map(|pre| COUNTRY_CODES.iter().find(|(c, _)| *c == pre))
        .map(|(c, n)| (*c, *n))
        .unwrap_or(("?", "Bilinmiyor"));
    let national = digits.strip_prefix(cc).unwrap_or(digits);
    let line = if cc == "90" {
        match national.chars().next() {
            Some('5') => "mobil",
            Some('8') => "ozel ucretli/ucretsiz servis",
            Some('2' | '3' | '4') => "sabit hat",
            _ => "bilinmiyor",
        }
    } else {
        "bilinmiyor"
    };
    let wa = format!("https://wa.me/{digits}");
    Ok(json!({
        "e164": p,
        "ulke_kodu": cc,
        "ulke": country,
        "ulusal_numara": national,
        "hat_tipi": line,
        "arastirma_baglantilari": {
            "whatsapp": wa,
            "telegram": format!("https://t.me/{p}"),
            "google": format!("https://www.google.com/search?q=%22%2B{digits}%22+OR+%22{national}%22"),
        }
    }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn phone_tr() {
        let v = super::phone("+90 532 000 00 00").unwrap();
        assert_eq!(v["ulke"], "Turkiye");
        assert_eq!(v["hat_tipi"], "mobil");
    }

    #[test]
    fn sites_parse() {
        assert!(super::sites().len() >= 40);
    }

    #[test]
    fn links() {
        let b = r#"<a href="https://twitter.com/ali">x</a> <a href='https://github.com/ali/'>g</a> https://github.com/ali/repo https://example.com/x https://keybase.io/"#;
        let l = super::linked_accounts(b, "gitlab.com");
        assert!(l.contains(&"https://twitter.com/ali".to_string()));
        assert!(l.contains(&"https://github.com/ali".to_string()));
        assert!(!l.iter().any(|x| x.contains("example.com")));
        assert!(!l.contains(&"https://keybase.io".to_string()));
    }

    #[test]
    fn vars() {
        assert!(super::variations("john.doe").contains(&"john_doe".to_string()));
    }
}
