// @name: openvpn-exposed
// @description: OpenVPN open
// @category: vpn
// @severity: info
// @tags: vpn, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 1194 { continue; }
    findings.push(#{ severity: "info", port: 1194, message: "OpenVPN open" });
}
