// @name: x11-6001-exposed
// @description: X11 display :1 reachable
// @category: misc
// @severity: high
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 6001 { continue; }
    findings.push(#{ severity: "high", port: 6001, message: "X11 display :1 reachable" });
}
