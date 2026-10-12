// @name: ident-service
// @description: ident/auth service open (user disclosure)
// @category: misc
// @severity: low
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 113 { continue; }
    findings.push(#{ severity: "low", port: 113, message: "ident/auth service open (user disclosure)" });
}
