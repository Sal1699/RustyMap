// @name: l2tp-exposed
// @description: L2TP VPN open
// @category: vpn
// @severity: info
// @tags: vpn, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 1701 { continue; }
    findings.push(#{ severity: "info", port: 1701, message: "L2TP VPN open" });
}
