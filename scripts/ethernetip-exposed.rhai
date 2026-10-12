// @name: ethernetip-exposed
// @description: EtherNet/IP open (ICS — must be isolated)
// @category: ics
// @severity: high
// @tags: ics, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 44818 { continue; }
    findings.push(#{ severity: "high", port: 44818, message: "EtherNet/IP open (ICS — must be isolated)" });
}
