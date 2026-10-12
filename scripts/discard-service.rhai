// @name: discard-service
// @description: discard service open (legacy)
// @category: misc
// @severity: low
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 9 { continue; }
    findings.push(#{ severity: "low", port: 9, message: "discard service open (legacy)" });
}
