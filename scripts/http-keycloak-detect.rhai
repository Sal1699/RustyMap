// @name: http-keycloak-detect
// @description: Keycloak IAM detected
// @category: http
// @severity: info
// @tags: http, http
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 && p.port != 8443 && p.port != 8000 && p.port != 8888 && p.port != 9000 { continue; }
    let scheme = if p.port == 443 || p.port == 8443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/auth/realms/master`, 3000);
    if type_of(resp.body) != "string" { continue; }
    if (resp.status == 200 || resp.status == 401 || resp.status == 302) && resp.body.to_lower().contains("keycloak") {
        findings.push(#{ severity: "info", port: p.port, message: `Keycloak IAM detected (${scheme}://${host.ip}:${p.port}/auth/realms/master)` });
    }
}
