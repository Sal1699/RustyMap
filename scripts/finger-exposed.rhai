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
    let b = svc.banner;
    if type_of(b) != "string" { continue; }
    if b.to_lower().contains("finger") {
        findings.push(#{ severity: "medium", port: 79, message: `Finger service (user enumeration): ${b.trim()}` });
    }
}
