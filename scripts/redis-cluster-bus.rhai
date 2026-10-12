// @name: redis-cluster-bus
// @description: Redis cluster bus port open
// @category: db
// @severity: low
// @tags: db, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 16379 { continue; }
    findings.push(#{ severity: "low", port: 16379, message: "Redis cluster bus port open" });
}
