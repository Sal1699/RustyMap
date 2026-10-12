// @name: http-wp-debug-log
// @description: WordPress debug.log exposed
// @category: http
// @severity: medium
// @tags: http, http
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 && p.port != 8443 && p.port != 8000 && p.port != 8888 && p.port != 9000 { continue; }
    let scheme = if p.port == 443 || p.port == 8443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/wp-content/debug.log`, 3000);
    if type_of(resp.body) != "string" { continue; }
    if resp.status == 200 && resp.body.to_lower().contains("php") {
        findings.push(#{ severity: "medium", port: p.port, message: `WordPress debug.log exposed (${scheme}://${host.ip}:${p.port}/wp-content/debug.log)` });
    }
}
