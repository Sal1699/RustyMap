// @name: http-env-exposed
// @description: Detect a publicly readable .env file (leaked secrets)
// @category: http
// @severity: critical
// @tags: http, secrets, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 && p.port != 8443 { continue; }
    let scheme = if p.port == 443 || p.port == 8443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/.env`, 3000);
    if resp.status != 200 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    // Look for typical dotenv keys to avoid flagging an HTML 200 page.
    if regex_match("(?im)^(APP_KEY|DB_PASSWORD|SECRET|AWS_ACCESS_KEY_ID|API_KEY|DATABASE_URL)\\s*=", body) {
        findings.push(#{
            severity: "critical",
            port: p.port,
            message: "publicly readable /.env — application secrets (DB/API/keys) are exposed"
        });
    }
}
