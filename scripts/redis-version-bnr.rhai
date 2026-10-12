// @name: redis-version-bnr
// @description: Redis version banner exposed
// @category: db
// @severity: low
// @tags: db, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 6379 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let b = svc.banner;
    if type_of(b) != "string" { continue; }
    if b.to_lower().contains("redis_version") {
        findings.push(#{ severity: "low", port: 6379, message: `Redis version banner exposed: ${b.trim()}` });
    }
}
