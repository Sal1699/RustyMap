// @name: http-prometheus-fed
// @description: Prometheus /federate exposed
// @category: http
// @severity: low
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
    let resp = http_get(`${base}/federate`, 3000);
    if type_of(resp.body) != "string" { continue; }
    let lo = resp.body.to_lower();
    if resp.status == 200 && lo.contains("# help") {
        if nx200 && ("# help" == "" || nxlo.contains("# help")) { continue; }
        findings.push(#{ severity: "low", port: p.port, message: `Prometheus /federate exposed (${base}/federate)` });
    }
}
