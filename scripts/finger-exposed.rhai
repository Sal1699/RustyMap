// @name: finger-exposed
// @description: Finger service (user enumeration)
// @category: misc
// @severity: medium
// @tags: misc, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 79 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let s = "";
    if type_of(svc.banner) == "string" { s += svc.banner.to_lower() + " "; }
    if type_of(svc.product) == "string" { s += svc.product.to_lower() + " "; }
    if type_of(svc.version) == "string" { s += svc.version.to_lower() + " "; }
    if s == "" { continue; }
    if s.contains("finger") {
        findings.push(#{ severity: "medium", port: 79, message: `Finger service (user enumeration): ${s.trim()}` });
    }
}
