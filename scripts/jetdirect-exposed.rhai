// @name: jetdirect-exposed
// @description: Printer raw/JetDirect (9100) open
// @category: print
// @severity: low
// @tags: print, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 9100 { continue; }
    findings.push(#{ severity: "low", port: 9100, message: "Printer raw/JetDirect (9100) open" });
}
