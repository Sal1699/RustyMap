// @name: vnc-version-bnr
// @description: VNC (RFB) server
// @category: vnc
// @severity: low
// @tags: vnc, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5900 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let b = svc.banner;
    if type_of(b) != "string" { continue; }
    if b.to_lower().contains("rfb") {
        findings.push(#{ severity: "low", port: 5900, message: `VNC (RFB) server: ${b.trim()}` });
    }
}
