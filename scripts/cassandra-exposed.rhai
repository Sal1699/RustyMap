// @name: cassandra-exposed
// @description: Cassandra CQL open (restrict access)
// @category: db
// @severity: medium
// @tags: db, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 9042 { continue; }
    findings.push(#{ severity: "medium", port: 9042, message: "Cassandra CQL open (restrict access)" });
}
