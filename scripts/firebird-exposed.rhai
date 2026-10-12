// @name: firebird-exposed
// @description: Firebird SQL open
// @category: db
// @severity: medium
// @tags: db, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 3050 { continue; }
    findings.push(#{ severity: "medium", port: 3050, message: "Firebird SQL open" });
}
