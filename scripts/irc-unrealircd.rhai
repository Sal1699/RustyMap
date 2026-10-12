// @name: irc-unrealircd
// @description: UnrealIRCd (check backdoor CVE-2010-2075)
// @category: misc
// @severity: low
// @tags: misc, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 6667 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let b = svc.banner;
    if type_of(b) != "string" { continue; }
    if b.to_lower().contains("unreal") {
        findings.push(#{ severity: "low", port: 6667, message: `UnrealIRCd (check backdoor CVE-2010-2075): ${b.trim()}` });
    }
}
