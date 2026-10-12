// @name: sip-asterisk
// @description: Asterisk SIP/PBX
// @category: voip
// @severity: low
// @tags: voip, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5060 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let b = svc.banner;
    if type_of(b) != "string" { continue; }
    if b.to_lower().contains("asterisk") {
        findings.push(#{ severity: "low", port: 5060, message: `Asterisk SIP/PBX: ${b.trim()}` });
    }
}
