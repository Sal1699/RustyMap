// @name: mongodb-banner
// @description: MongoDB server
// @category: db
// @severity: info
// @tags: db, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 27017 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let b = svc.banner;
    if type_of(b) != "string" { continue; }
    if b.to_lower().contains("mongodb") {
        findings.push(#{ severity: "info", port: 27017, message: `MongoDB server: ${b.trim()}` });
    }
}
