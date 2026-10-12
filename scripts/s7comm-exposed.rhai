// @name: s7comm-exposed
// @description: Siemens S7comm open (PLC — must be isolated)
// @category: ics
// @severity: high
// @tags: ics, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 102 { continue; }
    findings.push(#{ severity: "high", port: 102, message: "Siemens S7comm open (PLC — must be isolated)" });
}
