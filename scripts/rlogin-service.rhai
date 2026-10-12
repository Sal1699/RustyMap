// @name: rlogin-service
// @description: rlogin open (cleartext login)
// @category: misc
// @severity: high
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 513 { continue; }
    findings.push(#{ severity: "high", port: 513, message: "rlogin open (cleartext login)" });
}
