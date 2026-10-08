//! Faz 2: Iliskilendirme ve parmak izi.
//! Grafikte ortak altyapi gostergelerini (takip kimligi, favicon, ad sunucusu, ASN,
//! kayit firmasi, IP) paylasan varliklari kumeler ve harici pivot baglantilari uretir.

use crate::pivot::{Graph, Kind};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Gostergenin ayirt edicilik agirligi (yuksek = ayni sahip olasiligi yuksek).
fn weight(k: Kind) -> u32 {
    match k {
        Kind::TrackingId => 10,
        Kind::FaviconHash => 6,
        Kind::Ip => 4,
        Kind::Registrar => 1,
        Kind::Nameserver => 2,
        Kind::Asn => 1,
        _ => 0,
    }
}

fn external_pivots(k: Kind, v: &str) -> Value {
    let enc = v.replace(' ', "+");
    match k {
        Kind::TrackingId => json!({
            "builtwith": format!("https://builtwith.com/relationships/tag/{v}"),
            "publicwww": format!("https://publicwww.com/websites/%22{v}%22/"),
            "spyonweb": format!("https://spyonweb.com/{v}"),
        }),
        Kind::FaviconHash => json!({
            "shodan": format!("https://www.shodan.io/search?query=http.favicon.hash%3A{v}"),
            "censys": format!("https://search.censys.io/search?resource=hosts&q=services.http.response.favicons.shodan_hash%3A{v}"),
            "fofa_sorgusu": format!("icon_hash=\"{v}\""),
        }),
        Kind::Asn => json!({
            "bgp_he": format!("https://bgp.he.net/{}", v.split_whitespace().next().unwrap_or(v)),
        }),
        Kind::Ip => json!({
            "shodan": format!("https://www.shodan.io/host/{v}"),
            "censys": format!("https://search.censys.io/hosts/{v}"),
        }),
        Kind::Nameserver => json!({
            "ayni_ns_arama": format!("https://www.google.com/search?q=%22{enc}%22+nameserver"),
        }),
        _ => Value::Null,
    }
}

pub fn analyze(g: &Graph) -> Value {
    // gosterge dugum id -> ona bagli varlik (domain/url) degerleri
    let mut shared: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for e in &g.kenarlar {
        let (Some(src), Some(dst)) = (g.dugumler.get(&e.kaynak), g.dugumler.get(&e.hedef)) else { continue };
        if weight(dst.tur) > 0 && matches!(src.tur, Kind::Domain | Kind::Url) {
            let host = url::Url::parse(&src.deger).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or(src.deger.clone());
            shared.entry(dst.id.clone()).or_default().insert(host);
        }
    }

    let mut clusters: Vec<Value> = shared
        .iter()
        .filter(|(_, members)| members.len() >= 2)
        .filter_map(|(gid, members)| {
            let n = g.dugumler.get(gid)?;
            Some(json!({
                "gosterge_turu": n.tur,
                "gosterge": n.deger,
                "agirlik": weight(n.tur),
                "varliklar": members,
                "yorum": match n.tur {
                    Kind::TrackingId => "Ayni analitik/reklam hesabi: buyuk olasilikla ayni sahip veya yonetici",
                    Kind::FaviconHash => "Ayni favicon: ortak sablon, urun veya altyapi",
                    Kind::Ip => "Ayni IP: ortak barindirma (paylasimli hosting olabilir)",
                    Kind::Nameserver => "Ortak ad sunucusu",
                    Kind::Registrar => "Ortak kayit firmasi (zayif gosterge)",
                    _ => "Ortak gosterge",
                },
            }))
        })
        .collect();
    clusters.sort_by(|a, b| b["agirlik"].as_u64().cmp(&a["agirlik"].as_u64()));

    // Varlik ciftleri icin toplam baglanti skoru
    let mut pair: BTreeMap<(String, String), u32> = BTreeMap::new();
    for (gid, members) in &shared {
        let w = g.dugumler.get(gid).map(|n| weight(n.tur)).unwrap_or(0);
        let m: Vec<&String> = members.iter().collect();
        for i in 0..m.len() {
            for j in i + 1..m.len() {
                *pair.entry((m[i].clone(), m[j].clone())).or_default() += w;
            }
        }
    }
    let mut links: Vec<Value> = pair
        .into_iter()
        .map(|((a, b), s)| json!({"a": a, "b": b, "skor": s, "guven": if s >= 10 { "yuksek" } else if s >= 5 { "orta" } else { "dusuk" }}))
        .collect();
    links.sort_by(|a, b| b["skor"].as_u64().cmp(&a["skor"].as_u64()));
    links.truncate(50);

    let pivots: Vec<Value> = g
        .dugumler
        .values()
        .filter(|n| matches!(n.tur, Kind::TrackingId | Kind::FaviconHash | Kind::Asn | Kind::Ip))
        .map(|n| json!({"tur": n.tur, "deger": n.deger, "baglantilar": external_pivots(n.tur, &n.deger)}))
        .collect();

    // Grafikte derece merkeziyeti (Degree Centrality): en cok baglantiya sahip kritik kilit dugumler
    let mut degrees: BTreeMap<String, usize> = BTreeMap::new();
    for e in &g.kenarlar {
        *degrees.entry(e.kaynak.clone()).or_default() += 1;
        *degrees.entry(e.hedef.clone()).or_default() += 1;
    }
    let mut central_nodes: Vec<Value> = degrees
        .into_iter()
        .filter_map(|(id, deg)| {
            let n = g.dugumler.get(&id)?;
            Some(json!({
                "id": id,
                "tur": n.tur,
                "deger": n.deger,
                "derece": deg,
                "kapsamda": n.kapsamda
            }))
        })
        .collect();
    central_nodes.sort_by(|a, b| b["derece"].as_u64().cmp(&a["derece"].as_u64()));
    central_nodes.truncate(15);

    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    for n in g.dugumler.values() {
        *by_kind.entry(format!("{:?}", n.tur)).or_default() += 1;
    }

    json!({
        "ozet": {"dugum": g.dugumler.len(), "kenar": g.kenarlar.len(), "tur_dagilimi": by_kind},
        "merkezi_dugumler": central_nodes,
        "kumeler": clusters,
        "varlik_baglantilari": links,
        "harici_pivotlar": pivots,
    })
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::pivot::{Edge, Node};

    fn node(id: &str, k: Kind, v: &str) -> Node {
        Node { id: id.into(), tur: k, deger: v.into(), derinlik: 0, kapsamda: true, veri: Value::Null }
    }

    #[test]
    fn shared_tracking() {
        let mut g = Graph::default();
        for (i, k, v) in [("a", Kind::Url, "https://a.com"), ("b", Kind::Url, "https://b.com"), ("t", Kind::TrackingId, "UA-1-1")] {
            g.dugumler.insert(i.into(), node(i, k, v));
        }
        g.kenarlar.push(Edge { kaynak: "a".into(), hedef: "t".into(), iliski: "x".into() });
        g.kenarlar.push(Edge { kaynak: "b".into(), hedef: "t".into(), iliski: "x".into() });
        let r = analyze(&g);
        assert_eq!(r["kumeler"][0]["gosterge"], "UA-1-1");
        assert_eq!(r["varlik_baglantilari"][0]["guven"], "yuksek");
        let top_central = &r["merkezi_dugumler"][0];
        assert_eq!(top_central["id"], "t");
        assert_eq!(top_central["derece"], 2);
    }
}

