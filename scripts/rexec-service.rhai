// @name: rexec-service
// @description: rexec open (cleartext remote exec)
// @category: misc
// @severity: high
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 512 { continue; }
    findings.push(#{ severity: "high", port: 512, message: "rexec open (cleartext remote exec)" });
}
