// @name: db2-exposed
// @description: IBM Db2 open (restrict to app tier)
// @category: db
// @severity: medium
// @tags: db, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 50000 { continue; }
    findings.push(#{ severity: "medium", port: 50000, message: "IBM Db2 open (restrict to app tier)" });
}
