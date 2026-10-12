// @name: winrm-http-exposed
// @description: WinRM HTTP open (cleartext remote mgmt)
// @category: mgmt
// @severity: high
// @tags: mgmt, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5985 { continue; }
    findings.push(#{ severity: "high", port: 5985, message: "WinRM HTTP open (cleartext remote mgmt)" });
}
