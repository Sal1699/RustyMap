// @name: http-weblogic-console
// @description: Oracle WebLogic console reachable
// @category: http
// @severity: medium
// @tags: http, http
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 && p.port != 8443 && p.port != 8000 && p.port != 8888 && p.port != 9000 { continue; }
    let scheme = if p.port == 443 || p.port == 8443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/console/login/LoginForm.jsp`, 3000);
    if type_of(resp.body) != "string" { continue; }
    if (resp.status == 200 || resp.status == 401 || resp.status == 302) && resp.body.to_lower().contains("weblogic") {
        findings.push(#{ severity: "medium", port: p.port, message: `Oracle WebLogic console reachable (${scheme}://${host.ip}:${p.port}/console/login/LoginForm.jsp)` });
    }
}
