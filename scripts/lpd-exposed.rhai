// @name: lpd-exposed
// @description: LPD printer daemon open
// @category: print
// @severity: info
// @tags: print, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 515 { continue; }
    findings.push(#{ severity: "info", port: 515, message: "LPD printer daemon open" });
}
