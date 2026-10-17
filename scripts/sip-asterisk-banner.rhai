// @name: sip-asterisk-banner
// @description: Asterisk SIP
// @category: sip
// @severity: info
// @tags: sip, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5060 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let s = "";
    if type_of(svc.banner) == "string" { s += svc.banner.to_lower() + " "; }
    if type_of(svc.product) == "string" { s += svc.product.to_lower() + " "; }
    if type_of(svc.version) == "string" { s += svc.version.to_lower() + " "; }
    if s == "" { continue; }
    if s.contains("asterisk") {
        findings.push(#{ severity: "info", port: 5060, message: `Asterisk SIP: ${s.trim()}` });
    }
}
