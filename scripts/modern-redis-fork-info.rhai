// @name: modern-redis-fork-info
// @description: Identify DragonflyDB / KeyDB / Valkey via INFO (unauth)
// @category: database
// @severity: high
// @tags: redis, dragonfly, keydb, valkey, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 6379 && p.port != 6380 { continue; }
    let resp = tcp_send(host.ip, p.port, "INFO\r\n", 2500);
    if resp == "" { continue; }
    let lo = resp.to_lower();
    if lo.index_of("noauth") >= 0 { continue; } // auth required — good
    let flavour = if lo.index_of("dragonfly") >= 0 { "DragonflyDB" }
        else if lo.index_of("keydb") >= 0 { "KeyDB" }
        else if lo.index_of("valkey") >= 0 { "Valkey" }
        else { "" };
    if flavour != "" {
        findings.push(#{ severity: "high", port: p.port, message: `${flavour} responded to INFO without auth — data is fully exposed. Require a password` });
    }
}
