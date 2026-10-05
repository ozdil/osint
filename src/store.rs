//! SQLite vaka ve bulgu deposu. Her bulgu SHA-256 ile butunluk ozetiyle saklanir.

use crate::config::{data_dir, ensure_dir};
use anyhow::Result;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open() -> Result<Self> {
        let dir = data_dir()?;
        ensure_dir(&dir)?;
        let path = dir.join("osint.db");
        if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            anyhow::bail!("Veritabani yolu sembolik bag; reddedildi");
        }
        let conn = Connection::open(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Self::init(conn)
    }

    #[cfg(test)]
    pub fn memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS cases(
                id INTEGER PRIMARY KEY, name TEXT NOT NULL, note TEXT, created TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS findings(
                id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                module TEXT NOT NULL, target TEXT NOT NULL, data TEXT NOT NULL,
                sha256 TEXT NOT NULL, created TEXT NOT NULL);",
        )?;
        Ok(Self { conn })
    }

    pub fn create_case(&self, name: &str, note: &str) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO cases(name, note, created) VALUES (?1, ?2, ?3)",
            params![name, note, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn list_cases(&self) -> Result<Vec<Value>> {
        let mut st = self.conn.prepare(
            "SELECT c.id, c.name, c.note, c.created, COUNT(f.id) FROM cases c
             LEFT JOIN findings f ON f.case_id = c.id GROUP BY c.id ORDER BY c.id DESC",
        )?;
        let rows = st.query_map([], |r| {
            Ok(json!({"id": r.get::<_, i64>(0)?, "ad": r.get::<_, String>(1)?, "not": r.get::<_, Option<String>>(2)?,
                      "olusturma": r.get::<_, String>(3)?, "bulgu_sayisi": r.get::<_, i64>(4)?}))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn add_finding(&self, case_id: i64, module: &str, target: &str, data: &Value) -> Result<String> {
        let txt = serde_json::to_string(data)?;
        let hash = hex::encode(Sha256::digest(txt.as_bytes()));
        self.conn.execute(
            "INSERT INTO findings(case_id, module, target, data, sha256, created) VALUES (?1,?2,?3,?4,?5,?6)",
            params![case_id, module, target, txt, hash, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(hash)
    }

    pub fn case(&self, id: i64) -> Result<Value> {
        let (name, note, created): (String, Option<String>, String) = self.conn.query_row(
            "SELECT name, note, created FROM cases WHERE id=?1", [id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let mut st = self.conn.prepare("SELECT id, module, target, data, sha256, created FROM findings WHERE case_id=?1 ORDER BY id")?;
        let findings = st
            .query_map([id], |r| {
                let data: String = r.get(3)?;
                let hash: String = r.get(4)?;
                let ok = hex::encode(Sha256::digest(data.as_bytes())) == hash;
                Ok(json!({"id": r.get::<_, i64>(0)?, "modul": r.get::<_, String>(1)?, "hedef": r.get::<_, String>(2)?,
                          "veri": serde_json::from_str::<Value>(&data).unwrap_or(Value::Null),
                          "sha256": hash, "butunluk": if ok { "dogrulandi" } else { "BOZULMUS" },
                          "tarih": r.get::<_, String>(5)?}))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(json!({"id": id, "ad": name, "not": note, "olusturma": created, "bulgular": findings}))
    }

    pub fn delete_case(&self, id: i64) -> Result<bool> {
        Ok(self.conn.execute("DELETE FROM cases WHERE id=?1", [id])? > 0)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn roundtrip() {
        let s = super::Store::memory().unwrap();
        let id = s.create_case("deneme", "").unwrap();
        s.add_finding(id, "domain", "ornek.com", &serde_json::json!({"a": 1})).unwrap();
        let c = s.case(id).unwrap();
        assert_eq!(c["bulgular"][0]["butunluk"], "dogrulandi");
        assert_eq!(s.list_cases().unwrap()[0]["bulgu_sayisi"], 1);
    }
}
