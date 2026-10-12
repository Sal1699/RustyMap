// @name: ssh-huawei-detect
// @description: Huawei SSH device
// @category: ssh
// @severity: low
// @tags: ssh, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 22 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let b = svc.banner;
    if type_of(b) != "string" { continue; }
    if b.to_lower().contains("huawei") {
        findings.push(#{ severity: "low", port: 22, message: `Huawei SSH device: ${b.trim()}` });
    }
}
