// @name: smtp-exchange-bnr
// @description: Microsoft Exchange SMTP
// @category: smtp
// @severity: info
// @tags: smtp, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 25 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let b = svc.banner;
    if type_of(b) != "string" { continue; }
    if b.to_lower().contains("microsoft esmtp") {
        findings.push(#{ severity: "info", port: 25, message: `Microsoft Exchange SMTP: ${b.trim()}` });
    }
}
