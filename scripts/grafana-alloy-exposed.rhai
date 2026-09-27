// @name: grafana-alloy-exposed
// @description: Detect an exposed Grafana Alloy (OTel collector) UI
// @category: monitoring
// @severity: low
// @tags: grafana, alloy, otel
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 12345 { continue; }
    let resp = http_get(`http://${host.ip}:${p.port}/-/ready`, 3000);
    if resp.status == 200 {
        findings.push(#{ severity: "low", port: 12345, message: "Grafana Alloy UI/API reachable — its config can reveal scrape targets and credentials; restrict access" });
    }
}
