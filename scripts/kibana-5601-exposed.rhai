// @name: kibana-5601-exposed
// @description: Kibana (5601) open (check auth)
// @category: http
// @severity: medium
// @tags: http, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5601 { continue; }
    findings.push(#{ severity: "medium", port: 5601, message: "Kibana (5601) open (check auth)" });
}
