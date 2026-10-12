// @name: couchdb-native-exp
// @description: CouchDB HTTP open (check auth)
// @category: db
// @severity: medium
// @tags: db, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5984 { continue; }
    findings.push(#{ severity: "medium", port: 5984, message: "CouchDB HTTP open (check auth)" });
}
