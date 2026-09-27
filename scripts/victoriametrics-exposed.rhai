// @name: victoriametrics-exposed
// @description: Detect an exposed VictoriaMetrics instance
// @category: monitoring
// @severity: medium
// @tags: victoriametrics, metrics, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8428 { continue; }
    let resp = http_get(`http://${host.ip}:${p.port}/api/v1/status/tsdb`, 3000);
    if resp.status != 200 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if body.index_of("\"status\"") >= 0 || body.index_of("seriesCountByMetricName") >= 0 {
        findings.push(#{ severity: "medium", port: 8428, message: "VictoriaMetrics open — metrics and label cardinality are queryable without auth" });
    }
}
