// @name: chargen-service
// @description: chargen open (DDoS amplification vector)
// @category: misc
// @severity: medium
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 19 { continue; }
    findings.push(#{ severity: "medium", port: 19, message: "chargen open (DDoS amplification vector)" });
}
