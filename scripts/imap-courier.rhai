// @name: imap-courier
// @description: Courier IMAP
// @category: mail
// @severity: info
// @tags: mail, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 143 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let b = svc.banner;
    if type_of(b) != "string" { continue; }
    if b.to_lower().contains("courier") {
        findings.push(#{ severity: "info", port: 143, message: `Courier IMAP: ${b.trim()}` });
    }
}
