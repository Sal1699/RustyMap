// @name: ipp-cups-exposed
// @description: IPP/CUPS printing service open
// @category: print
// @severity: info
// @tags: print, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 631 { continue; }
    findings.push(#{ severity: "info", port: 631, message: "IPP/CUPS printing service open" });
}
