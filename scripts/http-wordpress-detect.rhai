// @name: http-wordpress-detect
// @description: Detect WordPress and its version from the generator tag
// @category: http
// @severity: info
// @tags: http, wordpress, cms
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 { continue; }
    let scheme = if p.port == 443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/`, 3000);
    if resp.status == 0 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if body.index_of("/wp-content/") >= 0 || body.index_of("wp-includes") >= 0 {
        let ver = regex_capture("(?i)content=\"WordPress\\s+([\\d.]+)\"", body);
        let msg = if ver != "" { `WordPress ${ver} detected` } else { "WordPress detected" };
        findings.push(#{ severity: "info", port: p.port, message: msg });
    }
}
