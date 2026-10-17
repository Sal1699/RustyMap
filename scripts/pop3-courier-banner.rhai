// @name: pop3-courier-banner
// @description: Courier POP3
// @category: pop3
// @severity: info
// @tags: pop3, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 110 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let s = "";
    if type_of(svc.banner) == "string" { s += svc.banner.to_lower() + " "; }
    if type_of(svc.product) == "string" { s += svc.product.to_lower() + " "; }
    if type_of(svc.version) == "string" { s += svc.version.to_lower() + " "; }
    if s == "" { continue; }
    if s.contains("courier") {
        findings.push(#{ severity: "info", port: 110, message: `Courier POP3: ${s.trim()}` });
    }
}
