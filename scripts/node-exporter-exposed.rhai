// @name: node-exporter-exposed
// @description: Detect an exposed Prometheus node_exporter /metrics
// @category: monitoring
// @severity: medium
// @tags: prometheus, node-exporter, info-leak
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 9100 { continue; }
    let resp = http_get(`http://${host.ip}:${p.port}/metrics`, 3000);
    if resp.status != 200 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if body.index_of("node_cpu_seconds_total") >= 0 || body.index_of("node_exporter_build_info") >= 0 {
        findings.push(#{ severity: "medium", port: 9100, message: "node_exporter /metrics exposed — leaks host inventory, mounts, users, kernel/uptime" });
    }
}
