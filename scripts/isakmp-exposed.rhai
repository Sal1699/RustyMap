// @name: isakmp-exposed
// @description: IKE/ISAKMP open (check aggressive mode)
// @category: vpn
// @severity: info
// @tags: vpn, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 500 { continue; }
    findings.push(#{ severity: "info", port: 500, message: "IKE/ISAKMP open (check aggressive mode)" });
}
