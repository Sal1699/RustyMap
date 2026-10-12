// @name: kibana-5601-exposed
// @description: Kibana
// @category: http
// @severity: medium
// @tags: http, exposure, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5601 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let s = "";
    if type_of(svc.banner) == "string" { s += svc.banner.to_lower() + " "; }
    if type_of(svc.product) == "string" { s += svc.product.to_lower() + " "; }
    if type_of(svc.version) == "string" { s += svc.version.to_lower() + " "; }
    if s == "" { continue; }
    if s.contains("kibana") {
        findings.push(#{ severity: "medium", port: 5601, message: `Kibana confirmed on ${p.port}: ${s.trim()}` });
    }
}
