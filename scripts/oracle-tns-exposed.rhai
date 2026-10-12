// @name: oracle-tns-exposed
// @description: Oracle TNS listener open (restrict to app tier)
// @category: db
// @severity: medium
// @tags: db, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 1521 { continue; }
    findings.push(#{ severity: "medium", port: 1521, message: "Oracle TNS listener open (restrict to app tier)" });
}
