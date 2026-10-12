// @name: pop3-dovecot
// @description: Dovecot POP3
// @category: mail
// @severity: info
// @tags: mail, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 110 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let b = svc.banner;
    if type_of(b) != "string" { continue; }
    if b.to_lower().contains("dovecot") {
        findings.push(#{ severity: "info", port: 110, message: `Dovecot POP3: ${b.trim()}` });
    }
}
