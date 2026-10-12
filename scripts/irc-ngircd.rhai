// @name: irc-ngircd
// @description: ngIRCd IRC server
// @category: misc
// @severity: info
// @tags: misc, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 6667 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let b = svc.banner;
    if type_of(b) != "string" { continue; }
    if b.to_lower().contains("ngircd") {
        findings.push(#{ severity: "info", port: 6667, message: `ngIRCd IRC server: ${b.trim()}` });
    }
}
