// @name: zookeeper-ruok
// @description: Apache ZooKeeper four-letter-word admin commands reachable
// @category: coordination
// @severity: medium
// @tags: zookeeper, 4lw, no-auth, exposure
// @author: rustymap
// ZooKeeper's "four letter words" are unauthenticated: "ruok"→"imok" proves
// the admin interface is open, and "stat" leaks the version plus every
// connected client IP. Whitelisting 4lw commands is the documented hardening.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 2181 && p.port != 2888 && p.port != 3888 { continue; }
    let ruok = tcp_send(host.ip, p.port, "ruok", 2500);
    if ruok.index_of("imok") < 0 { continue; }
    let stat = tcp_send(host.ip, p.port, "stat", 2500);
    let ver = regex_capture("(?i)version:\\s*([^\\r\\n,]+)", stat);
    let msg = if ver != "" {
        `ZooKeeper 4lw admin reachable (no auth) — version ${ver}`
    } else {
        "ZooKeeper 4lw admin reachable (ruok→imok, no auth)"
    };
    findings.push(#{ severity: "medium", port: p.port, message: msg });
}
