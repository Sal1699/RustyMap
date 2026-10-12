// @name: telnet-linux-login
// @description: Telnet login prompt (cleartext)
// @category: telnet
// @severity: medium
// @tags: telnet, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 23 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let b = svc.banner;
    if type_of(b) != "string" { continue; }
    if b.to_lower().contains("login:") {
        findings.push(#{ severity: "medium", port: 23, message: `Telnet login prompt (cleartext): ${b.trim()}` });
    }
}
