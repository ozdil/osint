//! Kimlik istihbarati: kullanici adi platform taramasi, e-posta, telefon.

use crate::{config::Config, http::Http, modules::domain::dns, validate};
use anyhow::Result;
use futures::{stream, StreamExt};
use md5::{Digest, Md5};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize, Clone)]
struct Site {
    ad: String,
    url: String,
    kontrol: String,
    #[serde(default)]
    yok: String,
}

fn sites() -> Vec<Site> {
    let mut s: Vec<Site> = serde_json::from_str(include_str!("../../data/sites.json")).unwrap_or_default();
    // Kullanici tanimli ek imzalar: ~/.config/osint/sites.json
    if let Some(p) = dirs::config_dir().map(|d| d.join("osint/sites.json")) {
        if let Ok(txt) = crate::config::read_limited(&p, 1024 * 1024) {
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
                    Ok(f) if s.kontrol == "metin_yok" => f.status == 200 && !f.body.contains(&s.yok),
                    Ok(f) => f.status == 200,
                    Err(_) => false,
                };
                found.then(|| json!({"platform": s.ad, "url": url.replace("/about.json", "").replace(".json", "")}))
            }
        })
        .buffer_unordered(24)
        .filter_map(|x| async { x })
        .collect()
        .await;
    let mut results = results;
    results.sort_by(|a, b| a["platform"].as_str().cmp(&b["platform"].as_str()));
    Ok(json!({
        "kullanici_adi": u,
        "taranan_platform": total,
        "bulunan": results.len(),
        "hesaplar": results,
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
            "google": format!("https://www.google.com/search?q=%22{p}%22+OR+%22{national}%22"),
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
    fn vars() {
        assert!(super::variations("john.doe").contains(&"john_doe".to_string()));
    }
}
