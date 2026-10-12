// @name: redis-sentinel-exp
// @description: Redis Sentinel open
// @category: db
// @severity: low
// @tags: db, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 26379 { continue; }
    findings.push(#{ severity: "low", port: 26379, message: "Redis Sentinel open" });
}
