//! Medya istihbarati: EXIF/GPS metaverisi ve dosya ozetleri.

use crate::config::Config;
use crate::http::Http;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

pub const MAX_MEDIA: u64 = 64 * 1024 * 1024;

pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path).with_context(|| format!("Dosya bulunamadi: {}", path.display()))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        bail!("Yalnizca normal dosyalar kabul edilir (sembolik bag reddedildi)");
    }
    let mut buf = Vec::new();
    std::fs::File::open(path)?.take(MAX_MEDIA + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_MEDIA {
        bail!("Dosya boyut siniri asildi ({} MiB)", MAX_MEDIA / 1024 / 1024);
    }
    Ok(buf)
}

fn gps_to_decimal(f: &exif::Field) -> Option<f64> {
    if let exif::Value::Rational(v) = &f.value {
        if v.len() >= 3 {
            return Some(v[0].to_f64() + v[1].to_f64() / 60.0 + v[2].to_f64() / 3600.0);
        }
    }
    None
}

pub fn exif_of(bytes: &[u8]) -> Value {
    let Ok(ex) = exif::Reader::new().read_from_container(&mut std::io::Cursor::new(bytes)) else {
        return json!({"durum": "EXIF verisi yok veya desteklenmeyen bicim"});
    };
    let mut tags = serde_json::Map::new();
    for f in ex.fields() {
        tags.insert(f.tag.to_string(), json!(f.display_value().with_unit(&ex).to_string()));
    }
    let get = |t| ex.get_field(t, exif::In::PRIMARY);
    let gps = match (get(exif::Tag::GPSLatitude), get(exif::Tag::GPSLongitude)) {
        (Some(la), Some(lo)) => {
            let mut lat = gps_to_decimal(la).unwrap_or(0.0);
            let mut lon = gps_to_decimal(lo).unwrap_or(0.0);
            if get(exif::Tag::GPSLatitudeRef).is_some_and(|r| r.display_value().to_string().contains('S')) {
                lat = -lat;
            }
            if get(exif::Tag::GPSLongitudeRef).is_some_and(|r| r.display_value().to_string().contains('W')) {
                lon = -lon;
            }
            json!({"enlem": lat, "boylam": lon, "harita": format!("https://www.openstreetmap.org/?mlat={lat:.6}&mlon={lon:.6}#map=17/{lat:.6}/{lon:.6}")})
        }
        _ => Value::Null,
    };
    let s = |t| get(t).map(|f| f.display_value().to_string());
    json!({
        "cihaz": {"marka": s(exif::Tag::Make), "model": s(exif::Tag::Model), "yazilim": s(exif::Tag::Software)},
        "cekim_tarihi": s(exif::Tag::DateTimeOriginal),
        "seri_no": s(exif::Tag::BodySerialNumber),
        "sahip": s(exif::Tag::CameraOwnerName).or(s(exif::Tag::Artist)),
        "gps": gps,
        "tum_etiketler": tags,
    })
}

pub fn hashes(bytes: &[u8]) -> Value {
    json!({
        "md5": hex::encode(md5::Md5::digest(bytes)),
        "sha1": hex::encode(Sha1::digest(bytes)),
        "sha256": hex::encode(Sha256::digest(bytes)),
    })
}

/// Belge metaverisi (PDF Info sozlugu ve OOXML docProps) icin basit cikarim.
pub fn document_meta(bytes: &[u8]) -> Value {
    let text = String::from_utf8_lossy(bytes);
    if bytes.starts_with(b"%PDF") {
        let mut m = serde_json::Map::new();
        for key in ["Author", "Creator", "Producer", "Title", "CreationDate", "ModDate", "Company"] {
            let pat = format!("/{key}(");
            if let Some(i) = text.find(&pat) {
                let rest = &text[i + pat.len()..];
                if let Some(e) = rest.find(')') {
                    m.insert(key.to_lowercase(), json!(rest[..e.min(200)].to_string()));
                }
            }
        }
        return json!({"tur": "PDF", "metaveri": m});
    }
    if bytes.starts_with(b"PK\x03\x04") {
        return ooxml_meta(bytes);
    }
    Value::Null
}

/// DOCX/XLSX/PPTX: docProps/core.xml ve app.xml. Her parca 1 MiB ile sinirli (zip bombasi korumasi).
fn ooxml_meta(bytes: &[u8]) -> Value {
    let Ok(mut z) = zip::ZipArchive::new(std::io::Cursor::new(bytes)) else { return Value::Null };
    let mut m = serde_json::Map::new();
    for part in ["docProps/core.xml", "docProps/app.xml"] {
        let Ok(f) = z.by_name(part) else { continue };
        let mut xml = String::new();
        if f.take(1024 * 1024).read_to_string(&mut xml).is_err() {
            continue;
        }
        for tag in ["dc:creator", "cp:lastModifiedBy", "dcterms:created", "dcterms:modified", "dc:title", "cp:revision", "Company", "Application", "AppVersion", "Manager", "Template", "TotalTime"] {
            if let Some(v) = xml_tag(&xml, tag) {
                m.insert(tag.rsplit(':').next().unwrap_or(tag).to_string(), json!(v));
            }
        }
    }
    if m.is_empty() { Value::Null } else { json!({"tur": "OOXML", "metaveri": m}) }
}

fn xml_tag(xml: &str, tag: &str) -> Option<String> {
    let s = xml.find(&format!("<{tag}"))?;
    let s = s + xml[s..].find('>')? + 1;
    let e = s + xml[s..].find(&format!("</{tag}>"))?;
    Some(xml[s..e].chars().take(200).collect())
}

/// Birden cok gorselin GPS konumlarini GeoJSON FeatureCollection olarak dondurur.
pub fn geojson(paths: &[String]) -> Value {
    let mut features = vec![];
    let mut skipped = vec![];
    for p in paths {
        let ex = read_file(Path::new(p)).map(|b| exif_of(&b));
        match ex {
            Ok(e) if e["gps"].is_object() => features.push(json!({
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [e["gps"]["boylam"], e["gps"]["enlem"]]},
                "properties": {"dosya": p, "tarih": e["cekim_tarihi"], "cihaz": e["cihaz"]},
            })),
            Ok(_) => skipped.push(json!({"dosya": p, "neden": "GPS yok"})),
            Err(err) => skipped.push(json!({"dosya": p, "neden": err.to_string()})),
        }
    }
    json!({"type": "FeatureCollection", "features": features, "atlanan": skipped,
           "not": "geojson.io veya QGIS ile acilabilir"})
}

pub async fn run(http: &Http, cfg: &Config, target: &str) -> Result<Value> {
    let path = Path::new(target);
    let bytes = read_file(path)?;
    let h = hashes(&bytes);
    let vt = match &cfg.virustotal_key {
        Some(k) => {
            let sha = h["sha256"].as_str().unwrap_or_default();
            http.json_with(&format!("https://www.virustotal.com/api/v3/files/{sha}"), 2 * 1024 * 1024, &[("x-apikey", k.as_str())])
                .await
                .map(|v| if v.is_null() { json!({"durum": "VirusTotal'da kayit yok"}) } else { v["data"]["attributes"]["last_analysis_stats"].clone() })
                .unwrap_or_else(|e| json!({"hata": e.to_string()}))
        }
        None => json!({"durum": "VirusTotal anahtari tanimli degil"}),
    };
    Ok(json!({
        "dosya": path.file_name().map(|n| n.to_string_lossy().to_string()),
        "boyut_bayt": bytes.len(),
        "ozetler": h,
        "exif": exif_of(&bytes),
        "belge": document_meta(&bytes),
        "virustotal": vt,
    }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn hash_known() {
        assert_eq!(super::hashes(b"abc")["sha256"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn docx_meta() {
        use std::io::Write;
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut buf);
            w.start_file("docProps/core.xml", zip::write::SimpleFileOptions::default()).unwrap();
            w.write_all(b"<cp:coreProperties><dc:creator>Ayse</dc:creator><cp:lastModifiedBy>Mehmet</cp:lastModifiedBy></cp:coreProperties>").unwrap();
            w.finish().unwrap();
        }
        let v = super::document_meta(buf.get_ref());
        assert_eq!(v["metaveri"]["creator"], "Ayse");
        assert_eq!(v["metaveri"]["lastModifiedBy"], "Mehmet");
    }

    #[test]
    fn pdf_meta() {
        let v = super::document_meta(b"%PDF-1.4 /Author(Ali Veli) /Producer(Word)");
        assert_eq!(v["metaveri"]["author"], "Ali Veli");
    }
}
