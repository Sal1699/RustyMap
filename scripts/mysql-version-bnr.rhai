// @name: mysql-version-bnr
// @description: MySQL server
// @category: db
// @severity: info
// @tags: db, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 3306 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let b = svc.banner;
    if type_of(b) != "string" { continue; }
    if b.to_lower().contains("mysql") {
        findings.push(#{ severity: "info", port: 3306, message: `MySQL server: ${b.trim()}` });
    }
}
