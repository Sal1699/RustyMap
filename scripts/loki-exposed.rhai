// @name: loki-exposed
// @description: Detect an unauthenticated Grafana Loki log API
// @category: monitoring
// @severity: high
// @tags: loki, logs, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 3100 { continue; }
    let resp = http_get(`http://${host.ip}:${p.port}/loki/api/v1/labels`, 3000);
    if resp.status != 200 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if body.index_of("\"status\"") >= 0 && body.index_of("success") >= 0 {
        findings.push(#{ severity: "high", port: 3100, message: "Grafana Loki API open without auth — logs (often with secrets/PII) are queryable" });
    }
}
