// @name: http-whatsupdocker-detect
// @description: WUD detected
// @category: http
// @severity: low
// @tags: http, detect
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 && p.port != 8443 && p.port != 8000 && p.port != 8888 { continue; }
    let scheme = if p.port == 443 || p.port == 8443 { "https" } else { "http" };
    let base = `${scheme}://${host.ip}:${p.port}`;
    let nx = http_get(`${base}/rustymap_nx_9z8y7x7`, 2500);
    let nx200 = type_of(nx.body) == "string" && nx.status == 200;
    let nxlo = if type_of(nx.body) == "string" { nx.body.to_lower() } else { "" };
    let resp = http_get(`${base}/`, 3000);
    if type_of(resp.body) != "string" { continue; }
    let lo = resp.body.to_lower();
    if (resp.status == 200 || resp.status == 401 || resp.status == 302 || resp.status == 403) && lo.contains("what's up docker") {
        if resp.status == 200 && nx200 && nxlo.contains("what's up docker") { continue; }
        findings.push(#{ severity: "low", port: p.port, message: `WUD detected (${base}/)` });
    }
}
