// @name: afp-exposed
// @description: Apple Filing Protocol (548) open
// @category: misc
// @severity: info
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 548 { continue; }
    findings.push(#{ severity: "info", port: 548, message: "Apple Filing Protocol (548) open" });
}
