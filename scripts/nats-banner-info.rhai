// @name: nats-banner-info
// @description: NATS server
// @category: misc
// @severity: info
// @tags: misc, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 4222 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let s = "";
    if type_of(svc.banner) == "string" { s += svc.banner.to_lower() + " "; }
    if type_of(svc.product) == "string" { s += svc.product.to_lower() + " "; }
    if type_of(svc.version) == "string" { s += svc.version.to_lower() + " "; }
    if s == "" { continue; }
    if s.contains("nats") {
        findings.push(#{ severity: "info", port: 4222, message: `NATS server: ${s.trim()}` });
    }
}
