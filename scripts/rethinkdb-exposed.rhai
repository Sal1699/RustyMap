// @name: rethinkdb-exposed
// @description: RethinkDB driver port open
// @category: db
// @severity: medium
// @tags: db, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 28015 { continue; }
    findings.push(#{ severity: "medium", port: 28015, message: "RethinkDB driver port open" });
}
