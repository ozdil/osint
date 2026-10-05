//! Boyut sinirli, SSRF korumali HTTP istemcisi.

use crate::validate::is_non_public;
use anyhow::{bail, Context, Result};
use reqwest::{redirect::Policy, Client, Response};
use std::time::Duration;
use url::Url;

pub const MAX_BODY: usize = 1024 * 1024; // 1 MiB
const UA: &str = "osint-platform/0.1 (+pasif-arastirma)";

#[derive(Clone)]
pub struct Http {
    client: Client,
    noredir: Client,
}

pub struct Fetched {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,

}

impl Http {
    pub fn new() -> Result<Self> {
        let build = |p: Policy| {
            Client::builder()
                .user_agent(UA)
                .timeout(Duration::from_secs(15))
                .connect_timeout(Duration::from_secs(8))
                .redirect(p)
                .build()
        };
        Ok(Self {
            client: build(Policy::limited(5))?,
            noredir: build(Policy::none())?,
        })
    }

    /// Bilinen, guvenilir API uc noktalari icin JSON getirir.
    pub async fn text(&self, url: &str, limit: usize) -> Result<String> {
        let resp = self.client.get(url).send().await?;
        if !resp.status().is_success() {
            bail!("HTTP {}: {url}", resp.status());
        }
        read_limited(resp, limit).await
    }

    /// Bilinen, guvenilir API uc noktalari icin JSON getirir.
    pub async fn json(&self, url: &str, limit: usize) -> Result<serde_json::Value> {
        self.json_with(url, limit, &[]).await
    }

    pub async fn json_with(
        &self,
        url: &str,
        limit: usize,
        headers: &[(&str, &str)],
    ) -> Result<serde_json::Value> {
        // Gecici hatalarda (429/502/503/504) ustel geri cekilmeyle en fazla 3 deneme.
        let mut attempt = 0u32;
        let resp = loop {
            let mut req = self.client.get(url);
            for (k, v) in headers {
                req = req.header(*k, *v);
            }
            let r = req.send().await.with_context(|| format!("Istek basarisiz: {url}"))?;
            let code = r.status().as_u16();
            if attempt < 2 && matches!(code, 429 | 502 | 503 | 504) {
                let wait = r
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok()?.parse::<u64>().ok())
                    .unwrap_or(2u64 << attempt)
                    .min(15);
                tokio::time::sleep(Duration::from_secs(wait)).await;
                attempt += 1;
                continue;
            }
            break r;
        };
        let status = resp.status();
        let body = read_limited(resp, limit).await?;
        if status.as_u16() == 404 {
            return Ok(serde_json::Value::Null);
        }
        if !status.is_success() {
            bail!("HTTP {status}: {url}");
        }
        serde_json::from_str(&body).with_context(|| format!("JSON ayristirilamadi: {url}"))
    }

    /// Kullanici kaynakli URL: genel olmayan hedefler reddedilir, yonlendirme takip edilmez.
    pub async fn fetch_untrusted(&self, url: &str) -> Result<Fetched> {
        check_public(url).await?;
        self.fetch(&self.noredir, url).await
    }

    pub async fn raw_untrusted(&self, url: &str) -> Result<Vec<u8>> {
        check_public(url).await?;
        let resp = self.noredir.get(url).send().await?;
        if !resp.status().is_success() {
            bail!("HTTP {}", resp.status());
        }
        read_bytes(resp, MAX_BODY).await
    }

    /// Bilinen bir platform URL'si icin yonlendirmesiz istek (kullanici adi taramasi).
    pub async fn probe(&self, url: &str) -> Result<Fetched> {
        self.fetch(&self.noredir, url).await
    }

    async fn fetch(&self, c: &Client, url: &str) -> Result<Fetched> {
        let resp = c.get(url).send().await?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = read_limited(resp, MAX_BODY).await.unwrap_or_default();
        Ok(Fetched { status, headers, body })
    }
}

async fn check_public(url: &str) -> Result<()> {
    {
        let parsed = Url::parse(url).context("Gecersiz URL")?;
        if !matches!(parsed.scheme(), "http" | "https") {
            bail!("Yalnizca http/https desteklenir");
        }
        let host = parsed.host_str().context("URL'de host yok")?;
        let port = parsed.port_or_known_default().unwrap_or(443);
        let addrs: Vec<_> = tokio::net::lookup_host((host, port))
            .await
            .with_context(|| format!("Cozumlenemedi: {host}"))?
            .collect();
        if addrs.is_empty() || addrs.iter().any(|a| is_non_public(&a.ip())) {
            bail!("Genel olmayan adrese istek engellendi (SSRF korumasi): {host}");
        }
        Ok(())
    }
}

/// Govdeyi en fazla `limit` bayt okur; asimda hata dondurur.
async fn read_bytes(mut resp: Response, limit: usize) -> Result<Vec<u8>> {
    if resp.content_length().is_some_and(|l| l as usize > limit) {
        bail!("Yanit boyut siniri asildi ({limit} bayt)");
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if buf.len() + chunk.len() > limit {
            bail!("Yanit boyut siniri asildi ({limit} bayt)");
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

async fn read_limited(resp: Response, limit: usize) -> Result<String> {
    Ok(String::from_utf8_lossy(&read_bytes(resp, limit).await?).into_owned())
}
