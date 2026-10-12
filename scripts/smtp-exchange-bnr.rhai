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
    let s = "";
    if type_of(svc.banner) == "string" { s += svc.banner.to_lower() + " "; }
    if type_of(svc.product) == "string" { s += svc.product.to_lower() + " "; }
    if type_of(svc.version) == "string" { s += svc.version.to_lower() + " "; }
    if s == "" { continue; }
    if s.contains("microsoft esmtp") {
        findings.push(#{ severity: "info", port: 25, message: `Microsoft Exchange SMTP: ${s.trim()}` });
    }
}
