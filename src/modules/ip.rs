//! IP istihbarati: geolokasyon/ASN, ters DNS, pasif acik servis bilgisi (Shodan InternetDB).

use crate::{http::Http, modules::domain::dns, validate};
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::net::IpAddr;

pub fn ptr_name(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v) => {
            let hex: String = v.octets().iter().map(|b| format!("{b:02x}")).collect();
            let mut s: Vec<String> = hex.chars().rev().map(|c| c.to_string()).collect();
            s.push("ip6.arpa".into());
            s.join(".")
        }
    }
}

pub async fn run(http: &Http, target: &str) -> Result<Value> {
    let ip = validate::ip(target)?;
    if validate::is_non_public(&ip) {
        bail!("Genel olmayan adres; pasif istihbarat kaynaklari bu adres icin anlamsizdir: {ip}");
    }
    let ptrn = ptr_name(&ip);
    let ips = ip.to_string();
    let u2 = format!("https://internetdb.shodan.io/{ip}");
    let (mut geo, ptr, idb) = tokio::join!(geo(http, &ips), dns(http, &ptrn, "PTR"), http.json(&u2, 256 * 1024));
    if geo["asn"].is_null() {
        if let Some((asn, name, prefix)) = cymru(http, &ip).await {
            geo["asn"] = json!(asn);
            if geo["kurum"].is_null() || geo["kaynak"].is_null() {
                geo["kurum"] = json!(name);
            }
            geo["onek"] = json!(prefix);
        }
    }
    Ok(json!({
        "ip": ip.to_string(),
        "konum": geo["konum"],
        "asn": geo["asn"],
        "kurum": geo["kurum"],
        "ag": geo["ag"],
        "bgp_onek": geo["onek"],
        "kaynak": geo["kaynak"],
        "kaynak_hatalari": geo["hatalar"],
        "ters_dns": ptr.unwrap_or_default().iter().map(|s| s.trim_end_matches('.')).collect::<Vec<_>>(),
        "pasif_servisler": match idb {
            Ok(Value::Null) => json!({"durum": "kayit yok"}),
            Ok(v) => json!({
                "portlar": v["ports"], "zafiyetler": v["vulns"],
                "etiketler": v["tags"], "host_adlari": v["hostnames"], "cpe": v["cpes"],
            }),
            Err(e) => json!({"hata": e.to_string()}),
        },
    }))
}

/// Team Cymru IP->ASN eslemesi (DNS TXT). HTTP kaynaklari engelli aglarda da calisir.
async fn cymru(http: &Http, ip: &IpAddr) -> Option<(String, String, String)> {
    let zone = match ip {
        IpAddr::V4(_) => "origin.asn.cymru.com",
        IpAddr::V6(_) => "origin6.asn.cymru.com",
    };
    let rev = ptr_name(ip);
    let rev = rev.trim_end_matches(".in-addr.arpa").trim_end_matches(".ip6.arpa");
    let txt = dns(http, &format!("{rev}.{zone}"), "TXT").await.ok()?;
    let f: Vec<String> = txt.first()?.split('|').map(|x| x.trim().to_string()).collect();
    let asn = f.first()?.split_whitespace().next()?.to_string();
    let name = dns(http, &format!("AS{asn}.asn.cymru.com"), "TXT").await.ok()
        .and_then(|t| t.first().and_then(|l| l.split('|').nth(4).map(|x| x.trim().to_string())))
        .unwrap_or_default();
    Some((format!("AS{asn}"), name, f.get(1).cloned().unwrap_or_default()))
}

/// Saglayici zinciri: ipinfo -> ipwho.is -> RDAP. Ilk basarili kaynak kullanilir, hatalar raporlanir.
async fn geo(http: &Http, ip: &str) -> Value {
    let mut errs = vec![];
    match http.json(&format!("https://ipinfo.io/{ip}/json"), 64 * 1024).await {
        Ok(v) if v["ip"].is_string() => {
            let (asn, org) = v["org"].as_str().and_then(|o| o.split_once(' ')).map(|(a, b)| (json!(a), json!(b))).unwrap_or((Value::Null, Value::Null));
            return json!({"kaynak": "ipinfo.io", "asn": asn, "kurum": org, "ag": Value::Null, "hatalar": errs,
                "konum": {"ulke": v["country"], "bolge": v["region"], "sehir": v["city"], "koordinat": v["loc"], "saat_dilimi": v["timezone"]}});
        }
        Ok(_) => errs.push("ipinfo.io: beklenmeyen yanit".to_string()),
        Err(e) => errs.push(format!("ipinfo.io: {e:#}")),
    }
    match http.json(&format!("https://ipwho.is/{ip}"), 64 * 1024).await {
        Ok(v) if v["success"] == true => {
            let c = &v["connection"];
            return json!({"kaynak": "ipwho.is", "asn": c["asn"].as_u64().map(|a| format!("AS{a}")), "kurum": c["org"], "ag": Value::Null, "hatalar": errs,
                "konum": {"ulke": v["country_code"], "bolge": v["region"], "sehir": v["city"],
                          "koordinat": format!("{},{}", v["latitude"], v["longitude"]), "saat_dilimi": v["timezone"]["id"]}});
        }
        Ok(_) => errs.push("ipwho.is: beklenmeyen yanit".to_string()),
        Err(e) => errs.push(format!("ipwho.is: {e:#}")),
    }
    match http.json(&format!("https://rdap.org/ip/{ip}"), 512 * 1024).await {
        Ok(v) if !v.is_null() => {
            let cidr = v["cidr0_cidrs"][0].as_object().map(|c| format!("{}/{}", c.get("v4prefix").or(c.get("v6prefix")).and_then(Value::as_str).unwrap_or(""), c.get("length").and_then(Value::as_u64).unwrap_or(0)));
            json!({"kaynak": "RDAP", "asn": Value::Null, "kurum": v["name"], "hatalar": errs,
                   "ag": {"ad": v["name"], "cidr": cidr, "baslangic": v["startAddress"], "bitis": v["endAddress"], "tur": v["type"]},
                   "konum": {"ulke": v["country"]}})
        }
        r => {
            if let Err(e) = r { errs.push(format!("RDAP: {e:#}")); }
            json!({"kaynak": Value::Null, "hatalar": errs, "konum": Value::Null})
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ptr() {
        assert_eq!(super::ptr_name(&"1.2.3.4".parse().unwrap()), "4.3.2.1.in-addr.arpa");
        assert!(super::ptr_name(&"2001:db8::1".parse().unwrap()).ends_with("8.b.d.0.1.0.0.2.ip6.arpa"));
    }
}
