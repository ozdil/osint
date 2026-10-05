//! Faz 1: Pivot motoru.
//! Bir tohum varliktan baslayarak bulgulardan yeni varliklar turetir ve derinlik sinirli
//! genislik oncelikli arama (BFS) ile bir iliski grafigi olusturur.

use crate::{config::Config, http::Http, modules, validate};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Domain,
    Ip,
    Url,
    Email,
    Username,
    Account,
    Asn,
    TrackingId,
    FaviconHash,
    Nameserver,
    Registrar,
    Technology,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "domain" => Self::Domain,
            "ip" => Self::Ip,
            "url" | "web" => Self::Url,
            "email" => Self::Email,
            "user" | "username" => Self::Username,
            _ => return None,
        })
    }

    /// Bu tur icin genisletme (yeni sorgu) yapilir mi?
    fn expandable(self) -> bool {
        matches!(self, Self::Domain | Self::Ip | Self::Url | Self::Email | Self::Username)
    }
}

#[derive(Serialize, Clone)]
pub struct Node {
    pub id: String,
    pub tur: Kind,
    pub deger: String,
    pub derinlik: u32,
    pub kapsamda: bool,
    #[serde(skip_serializing_if = "Value::is_null")]
    pub veri: Value,
}

#[derive(Serialize, Clone, PartialEq, Eq, Hash)]
pub struct Edge {
    pub kaynak: String,
    pub hedef: String,
    pub iliski: String,
}

#[derive(Serialize, Default)]
pub struct Graph {
    pub dugumler: BTreeMap<String, Node>,
    pub kenarlar: Vec<Edge>,
}

pub struct Options {
    pub max_depth: u32,
    pub max_nodes: usize,
    pub max_subdomains: usize,
    /// Kapsam disi alan adlari da genisletilsin mi?
    pub wide: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self { max_depth: 2, max_nodes: 150, max_subdomains: 20, wide: false }
    }
}

fn id(k: Kind, v: &str) -> String {
    format!("{k:?}:{v}").to_ascii_lowercase()
}

/// Kayit edilebilir kok alan adi (basit kamusal sonek sezgisi).
pub fn root_domain(d: &str) -> String {
    let parts: Vec<&str> = d.split('.').collect();
    let n = parts.len();
    if n < 2 {
        return d.to_string();
    }
    let sld = ["com", "net", "org", "gov", "edu", "co", "ac", "bel", "k12", "gen", "biz", "info", "av", "dr", "pol", "tsk", "web", "ltd", "plc", "ne", "or", "go"];
    if n >= 3 && parts[n - 1].len() == 2 && sld.contains(&parts[n - 2]) {
        parts[n - 3..].join(".")
    } else {
        parts[n - 2..].join(".")
    }
}

type Children = Vec<(Kind, String, String)>;

pub struct Engine<'a> {
    http: &'a Http,
    cfg: &'a Config,
    opts: Options,
    roots: HashSet<String>,
    pub graph: Graph,
}

impl<'a> Engine<'a> {
    pub fn new(http: &'a Http, cfg: &'a Config, opts: Options) -> Self {
        Self { http, cfg, opts, roots: HashSet::new(), graph: Graph::default() }
    }

    fn in_scope(&self, k: Kind, v: &str) -> bool {
        if self.opts.wide {
            return true;
        }
        match k {
            Kind::Domain | Kind::Url => {
                let host = url::Url::parse(v).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or(v.to_string());
                self.roots.contains(&root_domain(&host))
            }
            Kind::Email => v.rsplit_once('@').is_some_and(|(_, d)| self.roots.contains(&root_domain(d))),
            _ => true,
        }
    }

    fn add(&mut self, k: Kind, v: &str, depth: u32) -> (String, bool) {
        let i = id(k, v);
        if self.graph.dugumler.contains_key(&i) {
            return (i, false);
        }
        let kapsamda = self.in_scope(k, v);
        self.graph.dugumler.insert(i.clone(), Node { id: i.clone(), tur: k, deger: v.to_string(), derinlik: depth, kapsamda, veri: Value::Null });
        (i, true)
    }

    pub async fn run(&mut self, seed_kind: Kind, seed: &str, mut progress: impl FnMut(&str)) -> &Graph {
        let seed = seed.trim().to_string();
        match seed_kind {
            Kind::Domain => { if let Ok(d) = validate::domain(&seed) { self.roots.insert(root_domain(&d)); } }
            Kind::Email => { if let Ok((_, d)) = validate::email(&seed) { self.roots.insert(root_domain(&d)); } }
            Kind::Url => {
                if let Some(h) = url::Url::parse(&modules::web::normalize_url(&seed)).ok().and_then(|u| u.host_str().map(str::to_string)) {
                    self.roots.insert(root_domain(&h));
                }
            }
            _ => {}
        }
        let mut q = VecDeque::new();
        let (sid, _) = self.add(seed_kind, &seed, 0);
        q.push_back(sid);

        while let Some(nid) = q.pop_front() {
            let node = self.graph.dugumler[&nid].clone();
            if !node.tur.expandable() || !node.kapsamda || node.derinlik > self.opts.max_depth {
                continue;
            }
            progress(&format!("[d{}] {:?} {}", node.derinlik, node.tur, node.deger));
            let (data, children) = self.expand(node.tur, &node.deger).await;
            if let Some(n) = self.graph.dugumler.get_mut(&nid) {
                n.veri = data;
            }
            for (k, v, rel) in children {
                if self.graph.dugumler.len() >= self.opts.max_nodes {
                    break;
                }
                let (cid, new) = self.add(k, &v, node.derinlik + 1);
                let e = Edge { kaynak: nid.clone(), hedef: cid.clone(), iliski: rel };
                if !self.graph.kenarlar.contains(&e) {
                    self.graph.kenarlar.push(e);
                }
                if new && node.derinlik < self.opts.max_depth {
                    q.push_back(cid);
                }
            }
        }
        &self.graph
    }

    async fn expand(&self, k: Kind, v: &str) -> (Value, Children) {
        let r = match k {
            Kind::Domain => self.domain(v).await,
            Kind::Ip => self.ip(v).await,
            Kind::Url => self.url(v).await,
            Kind::Email => self.email(v).await,
            Kind::Username => self.username(v).await,
            _ => Ok((Value::Null, vec![])),
        };
        r.unwrap_or_else(|e| (json!({"hata": e.to_string()}), vec![]))
    }

    async fn domain(&self, d: &str) -> anyhow::Result<(Value, Children)> {
        let data = modules::domain::run(self.http, d).await?;
        let mut c: Children = vec![];
        let strs = |p: &str| -> Vec<String> {
            data.pointer(p).and_then(Value::as_array).into_iter().flatten().filter_map(|x| x.as_str().map(str::to_string)).collect()
        };
        for ip in strs("/dns/A").into_iter().chain(strs("/dns/AAAA")) {
            if validate::ip(&ip).is_ok() {
                c.push((Kind::Ip, ip, "cozumlenir".into()));
            }
        }
        for ns in strs("/dns/NS") {
            c.push((Kind::Nameserver, ns.trim_end_matches('.').to_string(), "ad_sunucusu".into()));
        }
        for mx in strs("/dns/MX") {
            if let Some(h) = mx.split_whitespace().last() {
                let h = h.trim_end_matches('.');
                if validate::domain(h).is_ok() {
                    c.push((Kind::Domain, h.to_string(), "posta_sunucusu".into()));
                }
            }
        }
        for cn in strs("/dns/CNAME") {
            c.push((Kind::Domain, cn.trim_end_matches('.').to_string(), "takma_ad".into()));
        }
        for s in strs("/alt_alan_adlari/liste").into_iter().filter(|s| s != d).take(self.opts.max_subdomains) {
            c.push((Kind::Domain, s, "alt_alan_adi".into()));
        }
        if let Some(r) = data.pointer("/rdap/kayit_firmasi").and_then(Value::as_str) {
            c.push((Kind::Registrar, r.to_string(), "kayit_firmasi".into()));
        }
        if !strs("/dns/A").is_empty() {
            c.push((Kind::Url, format!("https://{d}"), "web_sitesi".into()));
        }
        Ok((data, c))
    }

    async fn ip(&self, ip: &str) -> anyhow::Result<(Value, Children)> {
        let mut data = modules::ip::run(self.http, ip).await?;
        let mut c: Children = vec![];
        if let Some(a) = data["asn"].as_str() {
            c.push((Kind::Asn, format!("{a} {}", data["kurum"].as_str().unwrap_or("")).trim().to_string(), "asn".into()));
        }
        let hosts = data["ters_dns"].as_array().cloned().unwrap_or_default().into_iter()
            .chain(data.pointer("/pasif_servisler/host_adlari").and_then(Value::as_array).cloned().unwrap_or_default());
        for h in hosts.filter_map(|h| h.as_str().map(str::to_string)) {
            if validate::domain(&h).is_ok() {
                c.push((Kind::Domain, h, "ters_dns".into()));
            }
        }
        // Ayni IP'yi paylasan alan adlari (ters IP, anahtarsiz ve gunluk kotali kaynak)
        if let Ok(txt) = self.http.text(&format!("https://api.hackertarget.com/reverseiplookup/?q={ip}"), 256 * 1024).await {
            let list: Vec<String> = txt.lines().map(str::trim).filter(|l| validate::domain(l).is_ok()).map(str::to_string).take(30).collect();
            for h in &list {
                c.push((Kind::Domain, h.clone(), "ayni_ip".into()));
            }
            data["ayni_ip_alan_adlari"] = json!(list);
        }
        Ok((data, c))
    }

    async fn url(&self, u: &str) -> anyhow::Result<(Value, Children)> {
        let data = modules::web::run(self.http, u).await?;
        let mut c: Children = vec![];
        for e in data["epostalar"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            c.push((Kind::Email, e.to_string(), "sayfada_eposta".into()));
        }
        for t in data["takip_kimlikleri"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            c.push((Kind::TrackingId, t.to_string(), "takip_kimligi".into()));
        }
        if let Some(h) = data["favicon_mmh3"].as_i64() {
            c.push((Kind::FaviconHash, h.to_string(), "favicon".into()));
        }
        for t in data["teknolojiler"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            c.push((Kind::Technology, t.to_string(), "teknoloji".into()));
        }
        if let Some(loc) = data["yonlendirme"].as_str() {
            if let Some(h) = url::Url::parse(loc).ok().and_then(|x| x.host_str().map(str::to_string)) {
                c.push((Kind::Domain, h, "yonlendirir".into()));
            }
        }
        Ok((data, c))
    }

    async fn email(&self, e: &str) -> anyhow::Result<(Value, Children)> {
        let data = modules::identity::email(self.http, self.cfg, e).await?;
        let mut c: Children = vec![];
        if let Some(d) = data["alan_adi"].as_str() {
            if data["ucretsiz_saglayici"] != true {
                c.push((Kind::Domain, d.to_string(), "eposta_alani".into()));
            }
        }
        if let Some(u) = data["kullanici_adi_adayi"].as_str() {
            if validate::username(u).is_ok() && u.len() >= 4 && !["info", "admin", "contact", "iletisim", "bilgi", "support", "destek", "sales", "noreply"].contains(&u) {
                c.push((Kind::Username, u.to_string(), "kullanici_adi_adayi".into()));
            }
        }
        Ok((data, c))
    }

    async fn username(&self, u: &str) -> anyhow::Result<(Value, Children)> {
        let data = modules::identity::username(self.http, u).await?;
        let mut c: Children = data["hesaplar"].as_array().into_iter().flatten()
            .filter_map(|a| Some((Kind::Account, format!("{}: {}", a["platform"].as_str()?, a["url"].as_str()?), "hesap".into())))
            .collect();
        for a in data["hesaplar"].as_array().into_iter().flatten() {
            for e in a["epostalar"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                c.push((Kind::Email, e.to_string(), "profilde_eposta".into()));
            }
        }
        for l in data["capraz_baglantilar"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            c.push((Kind::Account, l.to_string(), "profilde_baglanti".into()));
        }
        Ok((data, c))
    }
}

#[cfg(test)]
mod tests {
    use super::root_domain;

    #[test]
    fn roots() {
        assert_eq!(root_domain("a.b.example.com"), "example.com");
        assert_eq!(root_domain("www.kastamonu.bel.tr"), "kastamonu.bel.tr");
        assert_eq!(root_domain("mail.ornek.com.tr"), "ornek.com.tr");
        assert_eq!(root_domain("x.co.uk"), "x.co.uk");
    }
}
