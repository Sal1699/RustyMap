// @name: winrm-https-exposed
// @description: WinRM HTTPS open (remote mgmt)
// @category: mgmt
// @severity: medium
// @tags: mgmt, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5986 { continue; }
    findings.push(#{ severity: "medium", port: 5986, message: "WinRM HTTPS open (remote mgmt)" });
}
