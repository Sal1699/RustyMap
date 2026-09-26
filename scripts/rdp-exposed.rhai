// @name: rdp-exposed
// @description: Flag RDP (3389) reachable and note NLA / BlueKeep exposure
// @category: rdp
// @severity: medium
// @tags: rdp, bluekeep, exposure
// @cve: CVE-2019-0708
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 3389 { continue; }
    findings.push(#{
        severity: "medium",
        port: 3389,
        message: "RDP (3389/tcp) exposed — require Network Level Authentication, restrict by firewall/VPN, and confirm the BlueKeep (CVE-2019-0708) patch is applied"
    });
}
