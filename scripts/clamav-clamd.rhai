// @name: clamav-clamd
// @description: Detect an exposed ClamAV clamd daemon (PING/PONG, VERSION)
// @category: antivirus
// @severity: medium
// @tags: clamav, clamd, exposure
// @author: rustymap
// clamd answers the clear-text command "PING" with "PONG" and "VERSION"
// with its engine + signature build. Reachable clamd lets anyone scan or
// shut down the AV engine (SHUTDOWN) with no authentication.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 3310 { continue; }
    let pong = tcp_send(host.ip, p.port, "PING\n", 2500);
    if pong.to_lower().index_of("pong") < 0 { continue; }
    let ver = tcp_send(host.ip, p.port, "VERSION\n", 2500);
    let label = regex_capture("(ClamAV [0-9][^\\r\\n]*)", ver);
    let msg = if label != "" {
        `clamd reachable with no auth — ${label}`
    } else {
        "clamd reachable with no auth (answered PING→PONG)"
    };
    findings.push(#{ severity: "medium", port: p.port, message: msg });
}
