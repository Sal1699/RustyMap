use crate::db::Db;
use anyhow::Result;
use serde_json::{json, Value};
use tiny_http::{Header, Response, Server};

const INDEX_HTML: &str = include_str!("../web/index.html");

pub fn serve(addr: &str, db_path: &str) -> Result<()> {
    let server = Server::http(addr).map_err(|e| anyhow::anyhow!("bind: {}", e))?;
    println!("RustyMap web UI listening on http://{}/", addr);
    for req in server.incoming_requests() {
        let url = req.url().to_string();
        let (body, content_type, status): (Vec<u8>, &str, u16) = match url.as_str() {
            "/" | "/index.html" => (INDEX_HTML.as_bytes().to_vec(), "text/html; charset=utf-8", 200),
            "/api/scans" => match api_scans(db_path) {
                Ok(v) => (v.to_string().into_bytes(), "application/json", 200),
                Err(e) => (json!({"error": e.to_string()}).to_string().into_bytes(), "application/json", 500),
            },
            u if u.starts_with("/api/scans/") => {
                let id: i64 = u.trim_start_matches("/api/scans/").parse().unwrap_or(-1);
                match api_scan_detail(db_path, id) {
                    Ok(v) => (v.to_string().into_bytes(), "application/json", 200),
                    Err(e) => (json!({"error": e.to_string()}).to_string().into_bytes(), "application/json", 500),
                }
            }
            _ => (b"not found".to_vec(), "text/plain", 404),
        };
        let mut resp = Response::from_data(body).with_status_code(status);
        resp.add_header(Header::from_bytes(&b"Content-Type"[..], content_type.as_bytes()).unwrap());
        let _ = req.respond(resp);
    }
    Ok(())
}

fn api_scans(db_path: &str) -> Result<Value> {
    let db = Db::open(db_path)?;
    let rows = db.list_scans()?;
    let arr: Vec<Value> = rows
        .into_iter()
        .map(|(id, started, stype, targets, ports, elapsed, status)| {
            json!({
                "id": id, "started_at": started, "scan_type": stype,
                "targets": targets, "ports": ports, "elapsed_secs": elapsed, "status": status,
            })
        })
        .collect();
    Ok(json!({ "scans": arr }))
}

fn api_scan_detail(db_path: &str, scan_id: i64) -> Result<Value> {
    let db = Db::open(db_path)?;
    let hosts = db.hosts_for_scan(scan_id)?;
    let mut out = Vec::new();
    for (hid, ip, hostname, up, latency) in hosts {
        let ports = db.ports_for_host(hid)?;
        let pv: Vec<Value> = ports
            .into_iter()
            .map(|(port, proto, state, service)| json!({
                "port": port, "protocol": proto, "state": state, "service": service,
            }))
            .collect();
        out.push(json!({
            "ip": ip, "hostname": hostname, "up": up, "latency_secs": latency, "ports": pv,
        }));
    }
    Ok(json!({ "scan_id": scan_id, "hosts": out }))
}
