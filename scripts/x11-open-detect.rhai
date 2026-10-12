// @name: x11-open-detect
// @description: X11 server reachable (often unauth)
// @category: misc
// @severity: high
// @tags: misc, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 6000 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let b = svc.banner;
    if type_of(b) != "string" { continue; }
    if b.to_lower().contains("x11") {
        findings.push(#{ severity: "high", port: 6000, message: `X11 server reachable (often unauth): ${b.trim()}` });
    }
}
