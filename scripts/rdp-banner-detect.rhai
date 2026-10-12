// @name: rdp-banner-detect
// @description: RDP service
// @category: rdp
// @severity: info
// @tags: rdp, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 3389 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let b = svc.banner;
    if type_of(b) != "string" { continue; }
    if b.to_lower().contains("rdp") {
        findings.push(#{ severity: "info", port: 3389, message: `RDP service: ${b.trim()}` });
    }
}
