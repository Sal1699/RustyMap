// @name: http-axis2-admin
// @description: Apache Axis2 admin exposed
// @category: http
// @severity: medium
// @tags: http, http
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 && p.port != 8443 && p.port != 8000 && p.port != 8888 && p.port != 9000 { continue; }
    let scheme = if p.port == 443 || p.port == 8443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/axis2/axis2-admin/`, 3000);
    if type_of(resp.body) != "string" { continue; }
    if resp.status == 200 && resp.body.to_lower().contains("axis2") {
        findings.push(#{ severity: "medium", port: p.port, message: `Apache Axis2 admin exposed (${scheme}://${host.ip}:${p.port}/axis2/axis2-admin/)` });
    }
}
