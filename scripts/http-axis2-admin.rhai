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
    let base = `${scheme}://${host.ip}:${p.port}`;
    let nx = http_get(`${base}/rustymap_nx_9z8y7x7`, 2500);
    let nx200 = type_of(nx.body) == "string" && nx.status == 200;
    let nxlo = if type_of(nx.body) == "string" { nx.body.to_lower() } else { "" };
    let resp = http_get(`${base}/axis2/axis2-admin/`, 3000);
    if type_of(resp.body) != "string" { continue; }
    let lo = resp.body.to_lower();
    if resp.status == 200 && lo.contains("axis2") {
        if nx200 && ("axis2" == "" || nxlo.contains("axis2")) { continue; }
        findings.push(#{ severity: "medium", port: p.port, message: `Apache Axis2 admin exposed (${base}/axis2/axis2-admin/)` });
    }
}
