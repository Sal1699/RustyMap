// @name: cups-admin-exposed
// @description: CUPS admin alt port open
// @category: print
// @severity: low
// @tags: print, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8631 { continue; }
    findings.push(#{ severity: "low", port: 8631, message: "CUPS admin alt port open" });
}
