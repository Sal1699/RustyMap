// @name: cockroachdb-exposed
// @description: CockroachDB open (restrict access)
// @category: db
// @severity: medium
// @tags: db, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 26257 { continue; }
    findings.push(#{ severity: "medium", port: 26257, message: "CockroachDB open (restrict access)" });
}
