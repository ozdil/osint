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
    let (u1, ptrn, u2) = (format!("https://ipinfo.io/{ip}/json"), ptr_name(&ip), format!("https://internetdb.shodan.io/{ip}"));
    let (geo, ptr, idb) = tokio::join!(
        http.json(&u1, 64 * 1024),
        dns(http, &ptrn, "PTR"),
        http.json(&u2, 256 * 1024),
    );
    let geo = geo.unwrap_or_else(|e| json!({"hata": e.to_string()}));
    let (asn, org) = geo["org"]
        .as_str()
        .and_then(|o| o.split_once(' '))
        .map(|(a, b)| (json!(a), json!(b)))
        .unwrap_or((Value::Null, Value::Null));
    Ok(json!({
        "ip": ip.to_string(),
        "konum": {
            "ulke": geo["country"], "bolge": geo["region"], "sehir": geo["city"],
            "koordinat": geo["loc"], "saat_dilimi": geo["timezone"],
        },
        "asn": asn,
        "kurum": org,
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

#[cfg(test)]
mod tests {
    #[test]
    fn ptr() {
        assert_eq!(super::ptr_name(&"1.2.3.4".parse().unwrap()), "4.3.2.1.in-addr.arpa");
        assert!(super::ptr_name(&"2001:db8::1".parse().unwrap()).ends_with("8.b.d.0.1.0.0.2.ip6.arpa"));
    }
}
