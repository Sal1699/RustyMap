// @name: postgres-banner
// @description: PostgreSQL server
// @category: db
// @severity: info
// @tags: db, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5432 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let b = svc.banner;
    if type_of(b) != "string" { continue; }
    if b.to_lower().contains("postgres") {
        findings.push(#{ severity: "info", port: 5432, message: `PostgreSQL server: ${b.trim()}` });
    }
}
