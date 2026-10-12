// @name: daytime-service
// @description: daytime service open (info leak/amplification)
// @category: misc
// @severity: low
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 13 { continue; }
    findings.push(#{ severity: "low", port: 13, message: "daytime service open (info leak/amplification)" });
}
