//! Girdi dogrulayicilari ve adres siniflandirma.

use anyhow::{bail, Result};
use std::net::IpAddr;

/// RFC 1035 uyumlu alan adini dogrular ve kucuk harfe cevirir.
pub fn domain(input: &str) -> Result<String> {
    let d = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() || d.len() > 253 || !d.contains('.') {
        bail!("Gecersiz alan adi: {input}");
    }
    for label in d.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        if !ok {
            bail!("Gecersiz alan adi etiketi: {label}");
        }
    }
    Ok(d)
}

pub fn ip(input: &str) -> Result<IpAddr> {
    input
        .trim()
        .parse::<IpAddr>()
        .map_err(|_| anyhow::anyhow!("Gecersiz IP adresi: {input}"))
}

pub fn email(input: &str) -> Result<(String, String)> {
    let e = input.trim().to_ascii_lowercase();
    let Some((local, dom)) = e.rsplit_once('@') else {
        bail!("Gecersiz e-posta: {input}");
    };
    let local_ok = !local.is_empty()
        && local.len() <= 64
        && local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._%+-".contains(c));
    if !local_ok {
        bail!("Gecersiz e-posta yerel kismi: {input}");
    }
    Ok((local.to_string(), domain(dom)?))
}

pub fn username(input: &str) -> Result<String> {
    let u = input.trim();
    if u.is_empty()
        || u.len() > 64
        || u.starts_with('.')
        || u.contains("..")
        || !u
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
    {
        bail!("Gecersiz kullanici adi (izinli: A-Z a-z 0-9 . _ -): {input}");
    }
    Ok(u.to_string())
}

/// E.164 formatina normalize eder: +[1-15 rakam].
pub fn phone(input: &str) -> Result<String> {
    let digits: String = input
        .chars()
        .filter(|c| !matches!(c, ' ' | '-' | '(' | ')' | '.'))
        .collect();
    let body = digits.strip_prefix('+').unwrap_or(&digits);
    let body = body.strip_prefix("00").unwrap_or(body);
    if body.len() < 7 || body.len() > 15 || !body.chars().all(|c| c.is_ascii_digit()) {
        bail!("Gecersiz telefon numarasi (E.164 bekleniyor): {input}");
    }
    Ok(format!("+{body}"))
}

/// Ozel (RFC 1918), yerel baglanti (RFC 3927), geri dongu ve benzeri genel olmayan adresler.
pub fn is_non_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64
                || v4.octets()[0] >= 224
        }
        IpAddr::V6(v6) => {
            let s = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || (s & 0xfe00) == 0xfc00
                || (s & 0xffc0) == 0xfe80
                || (s & 0xff00) == 0xff00
                || v6.to_ipv4_mapped().is_some_and(|m| is_non_public(&IpAddr::V4(m)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains() {
        assert_eq!(domain("Example.COM.").unwrap(), "example.com");
        assert!(domain("-bad.com").is_err());
        assert!(domain("nodot").is_err());
        assert!(domain("a b.com").is_err());
    }

    #[test]
    fn emails() {
        assert_eq!(email("A.b+x@Ex.org").unwrap().1, "ex.org");
        assert!(email("bad@@x").is_err());
        assert!(email("a;rm@x.com").is_err());
    }

    #[test]
    fn usernames() {
        assert!(username("john_doe.99").is_ok());
        assert!(username("../etc").is_err());
        assert!(username("..").is_err());
        assert!(username("a/b").is_err());
        assert!(username("a b").is_err());
    }

    #[test]
    fn phones() {
        assert_eq!(phone("+90 (532) 123-45-67").unwrap(), "+905321234567");
        assert_eq!(phone("0044 20 7946 0958").unwrap(), "+442079460958");
        assert!(phone("+12ab").is_err());
    }

    #[test]
    fn addresses() {
        assert!(is_non_public(&"10.0.0.1".parse().unwrap()));
        assert!(is_non_public(&"169.254.1.1".parse().unwrap()));
        assert!(is_non_public(&"127.0.0.1".parse().unwrap()));
        assert!(is_non_public(&"::ffff:192.168.1.1".parse().unwrap()));
        assert!(!is_non_public(&"1.1.1.1".parse().unwrap()));
    }
}
