// @name: pptp-exposed
// @description: PPTP VPN open (obsolete MPPE crypto)
// @category: vpn
// @severity: medium
// @tags: vpn, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 1723 { continue; }
    findings.push(#{ severity: "medium", port: 1723, message: "PPTP VPN open (obsolete MPPE crypto)" });
}
