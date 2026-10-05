//! Rapor uretici: JSON, Markdown, HTML.

use serde_json::Value;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

pub fn markdown(case: &Value) -> String {
    let mut o = format!(
        "# OSINT Vaka Raporu: {}\n\n- Vaka No: {}\n- Olusturma: {}\n- Rapor tarihi: {}\n- Bulgu sayisi: {}\n\n",
        case["ad"].as_str().unwrap_or(""),
        case["id"],
        case["olusturma"].as_str().unwrap_or(""),
        chrono::Utc::now().to_rfc3339(),
        case["bulgular"].as_array().map_or(0, Vec::len)
    );
    if let Some(n) = case["not"].as_str().filter(|n| !n.is_empty()) {
        o.push_str(&format!("> {n}\n\n"));
    }
    o.push_str("| No | Modul | Hedef | Tarih | Butunluk |\n|---|---|---|---|---|\n");
    for f in case["bulgular"].as_array().into_iter().flatten() {
        o.push_str(&format!("| {} | {} | `{}` | {} | {} |\n", f["id"], f["modul"].as_str().unwrap_or(""), f["hedef"].as_str().unwrap_or(""), f["tarih"].as_str().unwrap_or(""), f["butunluk"].as_str().unwrap_or("")));
    }
    for f in case["bulgular"].as_array().into_iter().flatten() {
        o.push_str(&format!(
            "\n## Bulgu {} - {} / {}\n\nSHA-256: `{}`\n\n```json\n{}\n```\n",
            f["id"], f["modul"].as_str().unwrap_or(""), f["hedef"].as_str().unwrap_or(""), f["sha256"].as_str().unwrap_or(""),
            serde_json::to_string_pretty(&f["veri"]).unwrap_or_default()
        ));
    }
    o
}

pub fn html(case: &Value) -> String {
    let mut rows = String::new();
    let mut body = String::new();
    for f in case["bulgular"].as_array().into_iter().flatten() {
        let g = |k: &str| esc(f[k].as_str().unwrap_or(""));
        rows.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>", f["id"], g("modul"), g("hedef"), g("tarih"), g("butunluk")));
        body.push_str(&format!(
            "<h2>Bulgu {} - {} / {}</h2><p class=meta>SHA-256: {}</p><pre>{}</pre>",
            f["id"], g("modul"), g("hedef"), g("sha256"),
            esc(&serde_json::to_string_pretty(&f["veri"]).unwrap_or_default())
        ));
    }
    format!(
        r#"<!doctype html><html lang="tr"><head><meta charset="utf-8"><title>OSINT Vaka Raporu</title>
<style>
body{{font-family:"Liberation Serif","Times New Roman",serif;font-size:12pt;margin:2.5cm;color:#000}}
h1{{font-size:14pt;text-align:center;text-transform:uppercase}} h2{{font-size:12pt;margin-top:1.5em}}
table{{border-collapse:collapse;width:100%;font-size:11pt}} td,th{{border:1px solid #444;padding:4px 6px;text-align:left}}
pre{{font-family:"JetBrainsMono Nerd Font","JetBrains Mono",monospace;font-size:9pt;white-space:pre-wrap;border:1px solid #ccc;padding:8px}}
.meta{{font-size:10pt;color:#333}}
</style></head><body>
<h1>Acik Kaynak Istihbarat Vaka Raporu</h1>
<p><b>Vaka:</b> {} &nbsp; <b>No:</b> {} &nbsp; <b>Olusturma:</b> {}</p>
<p class=meta>Rapor tarihi: {}. Tum bulgular kamuya acik kaynaklardan pasif yontemle elde edilmistir.</p>
<table><tr><th>No</th><th>Modul</th><th>Hedef</th><th>Tarih</th><th>Butunluk</th></tr>{}</table>{}</body></html>"#,
        esc(case["ad"].as_str().unwrap_or("")), case["id"], esc(case["olusturma"].as_str().unwrap_or("")),
        chrono::Utc::now().to_rfc3339(), rows, body
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn escapes() {
        let c = serde_json::json!({"ad": "<script>", "id": 1, "bulgular": []});
        assert!(!super::html(&c).contains("<script>"));
        assert!(super::markdown(&c).contains("# OSINT"));
    }
}
