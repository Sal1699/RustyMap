// @name: grafana-3000-exposed
// @description: Grafana (3000) open (check default admin)
// @category: http
// @severity: low
// @tags: http, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 3000 { continue; }
    findings.push(#{ severity: "low", port: 3000, message: "Grafana (3000) open (check default admin)" });
}
