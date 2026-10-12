// @name: winbox-exposed
// @description: MikroTik Winbox (8291) open
// @category: mgmt
// @severity: medium
// @tags: mgmt, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8291 { continue; }
    findings.push(#{ severity: "medium", port: 8291, message: "MikroTik Winbox (8291) open" });
}
