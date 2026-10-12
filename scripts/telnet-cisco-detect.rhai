// @name: telnet-cisco-detect
// @description: Cisco Telnet (cleartext mgmt)
// @category: telnet
// @severity: medium
// @tags: telnet, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 23 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let s = "";
    if type_of(svc.banner) == "string" { s += svc.banner.to_lower() + " "; }
    if type_of(svc.product) == "string" { s += svc.product.to_lower() + " "; }
    if type_of(svc.version) == "string" { s += svc.version.to_lower() + " "; }
    if s == "" { continue; }
    if s.contains("cisco") {
        findings.push(#{ severity: "medium", port: 23, message: `Cisco Telnet (cleartext mgmt): ${s.trim()}` });
    }
}
