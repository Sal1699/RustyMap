// @name: rsh-service
// @description: rsh/shell open (cleartext remote shell)
// @category: misc
// @severity: high
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 514 { continue; }
    findings.push(#{ severity: "high", port: 514, message: "rsh/shell open (cleartext remote shell)" });
}
