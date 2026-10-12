// @name: ldaps-exposed
// @description: LDAPS open (directory over TLS)
// @category: dir
// @severity: low
// @tags: dir, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 636 { continue; }
    findings.push(#{ severity: "low", port: 636, message: "LDAPS open (directory over TLS)" });
}
