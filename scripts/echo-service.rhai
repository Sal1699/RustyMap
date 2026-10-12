// @name: echo-service
// @description: echo service open (amplification/legacy)
// @category: misc
// @severity: low
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 7 { continue; }
    findings.push(#{ severity: "low", port: 7, message: "echo service open (amplification/legacy)" });
}
