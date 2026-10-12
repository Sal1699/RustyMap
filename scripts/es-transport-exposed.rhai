// @name: es-transport-exposed
// @description: Elasticsearch transport (9300) open
// @category: db
// @severity: medium
// @tags: db, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 9300 { continue; }
    findings.push(#{ severity: "medium", port: 9300, message: "Elasticsearch transport (9300) open" });
}
