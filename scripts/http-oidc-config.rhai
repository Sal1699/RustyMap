// @name: http-oidc-config
// @description: OIDC discovery endpoint present
// @category: http
// @severity: info
// @tags: http, http
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 && p.port != 8443 && p.port != 8000 && p.port != 8888 && p.port != 9000 { continue; }
    let scheme = if p.port == 443 || p.port == 8443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/.well-known/openid-configuration`, 3000);
    if type_of(resp.body) != "string" { continue; }
    if resp.status == 200 && resp.body.to_lower().contains("issuer") {
        findings.push(#{ severity: "info", port: p.port, message: `OIDC discovery endpoint present (${scheme}://${host.ip}:${p.port}/.well-known/openid-configuration)` });
    }
}
