// @name: http-spring-h2
// @description: Spring H2 database console exposed
// @category: http
// @severity: high
// @tags: http, http
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 && p.port != 8443 && p.port != 8000 && p.port != 8888 && p.port != 9000 { continue; }
    let scheme = if p.port == 443 || p.port == 8443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/h2-console/`, 3000);
    if type_of(resp.body) != "string" { continue; }
    if resp.status == 200 && resp.body.to_lower().contains("h2 console") {
        findings.push(#{ severity: "high", port: p.port, message: `Spring H2 database console exposed (${scheme}://${host.ip}:${p.port}/h2-console/)` });
    }
}
