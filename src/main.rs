mod config;
mod correlate;
mod http;
mod modules;
mod pivot;
mod report;
mod server;
mod store;
mod validate;

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json::Value;

#[derive(Parser)]
#[command(name = "osint", version, about = "Pasif acik kaynak istihbarat platformu")]
struct Cli {
    /// Bulguyu bu vakaya kaydet
    #[arg(long, global = true)]
    vaka: Option<i64>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Alan adi: DNS, RDAP, alt alan adlari, e-posta guvenligi
    Domain { hedef: String },
    /// IP: konum, ASN, ters DNS, pasif servisler
    Ip { hedef: String },
    /// Web: basliklar, teknoloji, takip kimlikleri, favicon, arsiv
    Web { hedef: String },
    /// Kullanici adi platform taramasi
    User { hedef: String },
    /// E-posta analizi
    Email { hedef: String },
    /// Telefon numarasi ayristirma
    Phone { hedef: String },
    /// Medya/belge metaverisi ve ozetler
    Media { dosya: String },
    /// Pivot motoru + iliskilendirme analizi
    Pivot {
        /// Tohum turu: domain, ip, url, email, user
        tur: String,
        hedef: String,
        #[arg(short, long, default_value_t = 2)]
        derinlik: u32,
        #[arg(long, default_value_t = 150)]
        max_dugum: usize,
        /// Kapsam disi alan adlarini da genislet
        #[arg(long)]
        genis: bool,
    },
    /// Vaka yonetimi
    Vaka {
        #[command(subcommand)]
        islem: VakaCmd,
    },
    /// Yapilandirma (API anahtarlari)
    Config {
        #[command(subcommand)]
        islem: ConfigCmd,
    },
    /// Yerel web panelini baslat
    Serve {
        #[arg(short, long, default_value_t = 8787)]
        port: u16,
    },
}

#[derive(Subcommand)]
enum VakaCmd {
    Yeni { ad: String, #[arg(long, default_value = "")] not: String },
    Liste,
    Rapor { id: i64, #[arg(long, default_value = "md")] bicim: String },
    Sil { id: i64 },
}

#[derive(Subcommand)]
enum ConfigCmd {
    Set { anahtar: String, deger: String },
    Show,
}

fn print(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

#[tokio::main]
async fn main() {
    if let Err(e) = real_main().await {
        eprintln!("Hata: {e:#}");
        std::process::exit(1);
    }
}

async fn real_main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = config::Config::load();
    let http = http::Http::new()?;
    let save = |module: &str, target: &str, v: &Value| -> Result<()> {
        if let Some(id) = cli.vaka {
            let h = store::Store::open()?.add_finding(id, module, target, v)?;
            eprintln!("Vaka {id} kaydedildi (sha256 {h})");
        }
        Ok(())
    };

    let simple = match &cli.cmd {
        Cmd::Domain { hedef } => Some(("domain", hedef)),
        Cmd::Ip { hedef } => Some(("ip", hedef)),
        Cmd::Web { hedef } => Some(("web", hedef)),
        Cmd::User { hedef } => Some(("user", hedef)),
        Cmd::Email { hedef } => Some(("email", hedef)),
        Cmd::Phone { hedef } => Some(("phone", hedef)),
        Cmd::Media { dosya } => Some(("media", dosya)),
        _ => None,
    };
    if let Some((m, t)) = simple {
        let v = modules::dispatch(&http, &cfg, m, t).await?;
        print(&v);
        return save(m, t, &v);
    }

    match &cli.cmd {
        Cmd::Pivot { tur, hedef, derinlik, max_dugum, genis } => {
            let k = pivot::Kind::parse(tur).ok_or_else(|| anyhow::anyhow!("Gecersiz tur: domain, ip, url, email, user"))?;
            let opts = pivot::Options { max_depth: (*derinlik).min(4), max_nodes: (*max_dugum).min(500), wide: *genis, ..Default::default() };
            let mut eng = pivot::Engine::new(&http, &cfg, opts);
            let g = eng.run(k, hedef, |m| eprintln!("  {m}")).await;
            let v = serde_json::json!({"grafik": g, "analiz": correlate::analyze(g)});
            print(&v);
            save("pivot", hedef, &v)?;
        }
        Cmd::Vaka { islem } => {
            let s = store::Store::open()?;
            match islem {
                VakaCmd::Yeni { ad, not } => println!("Vaka olusturuldu: {}", s.create_case(ad, not)?),
                VakaCmd::Liste => print(&Value::Array(s.list_cases()?)),
                VakaCmd::Rapor { id, bicim } => {
                    let c = s.case(*id)?;
                    match bicim.as_str() {
                        "html" => println!("{}", report::html(&c)),
                        "json" => print(&c),
                        _ => println!("{}", report::markdown(&c)),
                    }
                }
                VakaCmd::Sil { id } => {
                    s.delete_case(*id)?;
                    println!("Vaka silindi: {id}");
                }
            }
        }
        Cmd::Config { islem } => match islem {
            ConfigCmd::Set { anahtar, deger } => {
                config::Config::set(anahtar, deger)?;
                println!("Kaydedildi: {anahtar}");
            }
            ConfigCmd::Show => {
                for k in config::KEYS {
                    let set = match *k {
                        "hibp_key" => cfg.hibp_key.is_some(),
                        "virustotal_key" => cfg.virustotal_key.is_some(),
                        "github_token" => cfg.github_token.is_some(),
                        _ => cfg.abuseipdb_key.is_some(),
                    };
                    println!("{k}: {}", if set { "tanimli" } else { "tanimsiz" });
                }
            }
        },
        Cmd::Serve { port } => server::serve(*port).await?,
        _ => unreachable!(),
    }
    Ok(())
}
