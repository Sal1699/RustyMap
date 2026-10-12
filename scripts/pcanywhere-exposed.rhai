// @name: pcanywhere-exposed
// @description: pcAnywhere open (legacy remote control)
// @category: mgmt
// @severity: medium
// @tags: mgmt, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5631 { continue; }
    findings.push(#{ severity: "medium", port: 5631, message: "pcAnywhere open (legacy remote control)" });
}
