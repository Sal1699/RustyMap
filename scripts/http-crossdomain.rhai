// @name: http-crossdomain
// @description: crossdomain.xml present (Flash policy)
// @category: http
// @severity: low
// @tags: http, http
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 && p.port != 8443 && p.port != 8000 && p.port != 8888 && p.port != 9000 { continue; }
    let scheme = if p.port == 443 || p.port == 8443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/crossdomain.xml`, 3000);
    if type_of(resp.body) != "string" { continue; }
    if resp.status == 200 && resp.body.to_lower().contains("cross-domain") {
        findings.push(#{ severity: "low", port: p.port, message: `crossdomain.xml present (Flash policy) (${scheme}://${host.ip}:${p.port}/crossdomain.xml)` });
    }
}
