use anyhow::Result;
use serde::Serialize;
use serde_json::json;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

pub struct Audit {
    file: Option<Mutex<std::fs::File>>,
}

impl Audit {
    pub fn open(path: Option<&str>) -> Result<Self> {
        let file = match path {
            Some(p) => Some(Mutex::new(
                OpenOptions::new().create(true).append(true).open(p)?,
            )),
            None => None,
        };
        Ok(Self { file })
    }

    pub fn event<T: Serialize>(&self, event: &str, payload: T) {
        let Some(ref f) = self.file else { return };
        let ts = chrono::Local::now().to_rfc3339();
        let line = json!({ "ts": ts, "event": event, "data": payload }).to_string();
        if let Ok(mut g) = f.lock() {
            let _ = writeln!(g, "{}", line);
        }
    }

    #[allow(dead_code)]
    pub fn simple(&self, event: &str, msg: &str) {
        self.event(event, json!({ "msg": msg }));
    }
}
