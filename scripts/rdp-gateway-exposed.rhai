// @name: rdp-gateway-exposed
// @description: RDP Gateway (3391) open
// @category: rdp
// @severity: low
// @tags: rdp, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 3391 { continue; }
    findings.push(#{ severity: "low", port: 3391, message: "RDP Gateway (3391) open" });
}
