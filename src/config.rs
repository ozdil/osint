//! Yapilandirma ve guvenli dosya islemleri.
//! Dosyalar atomik `.tmp_*` uzerinden yazilir; dosya 0600, dizin 0700; sembolik baglar reddedilir.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const MAX_CONFIG: u64 = 1024 * 1024;

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct Config {
    pub hibp_key: Option<String>,
    pub virustotal_key: Option<String>,
    pub github_token: Option<String>,
    pub abuseipdb_key: Option<String>,
}

pub const KEYS: &[&str] = &["hibp_key", "virustotal_key", "github_token", "abuseipdb_key"];

pub fn config_dir() -> Result<PathBuf> {
    let d = dirs::config_dir().context("Yapilandirma dizini bulunamadi")?.join("osint");
    ensure_dir(&d)?;
    Ok(d)
}

pub fn data_dir() -> Result<PathBuf> {
    let d = dirs::data_dir().context("Veri dizini bulunamadi")?.join("osint");
    ensure_dir(&d)?;
    Ok(d)
}

pub fn ensure_dir(d: &Path) -> Result<()> {
    if let Ok(m) = std::fs::symlink_metadata(d) {
        if m.file_type().is_symlink() {
            bail!("Sembolik bag reddedildi: {}", d.display());
        }
    } else {
        std::fs::create_dir_all(d)?;
    }
    std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

pub fn read_limited(p: &Path, max: u64) -> Result<String> {
    let m = std::fs::symlink_metadata(p)?;
    if m.file_type().is_symlink() {
        bail!("Sembolik bag reddedildi: {}", p.display());
    }
    let mut s = String::new();
    std::fs::File::open(p)?.take(max + 1).read_to_string(&mut s)?;
    if s.len() as u64 > max {
        bail!("Dosya boyut siniri asildi: {}", p.display());
    }
    Ok(s)
}

pub fn write_atomic(p: &Path, data: &[u8]) -> Result<()> {
    if std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink()) {
        bail!("Sembolik bag reddedildi: {}", p.display());
    }
    let dir = p.parent().context("Ust dizin yok")?;
    let tmp = dir.join(format!(".tmp_{}_{}", std::process::id(), p.file_name().unwrap_or_default().to_string_lossy()));
    {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, p).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    Ok(())
}

impl Config {
    pub fn load() -> Self {
        config_dir()
            .ok()
            .and_then(|d| read_limited(&d.join("config.toml"), MAX_CONFIG).ok())
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn set(key: &str, value: &str) -> Result<()> {
        let mut c = Self::load();
        let v = Some(value.trim().to_string()).filter(|s| !s.is_empty());
        match key {
            "hibp_key" => c.hibp_key = v,
            "virustotal_key" => c.virustotal_key = v,
            "github_token" => c.github_token = v,
            "abuseipdb_key" => c.abuseipdb_key = v,
            _ => bail!("Bilinmeyen anahtar. Gecerli: {}", KEYS.join(", ")),
        }
        write_atomic(&config_dir()?.join("config.toml"), toml::to_string(&c)?.as_bytes())
    }
}
