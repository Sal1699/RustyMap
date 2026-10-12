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
    let s = "";
    if type_of(svc.banner) == "string" { s += svc.banner.to_lower() + " "; }
    if type_of(svc.product) == "string" { s += svc.product.to_lower() + " "; }
    if type_of(svc.version) == "string" { s += svc.version.to_lower() + " "; }
    if s == "" { continue; }
    if s.contains("x11") {
        findings.push(#{ severity: "high", port: 6000, message: `X11 server reachable (often unauth): ${s.trim()}` });
    }
}
