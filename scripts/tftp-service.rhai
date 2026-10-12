// @name: tftp-service
// @description: TFTP open (no auth; config/firmware exposure)
// @category: misc
// @severity: high
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 69 { continue; }
    findings.push(#{ severity: "high", port: 69, message: "TFTP open (no auth; config/firmware exposure)" });
}
