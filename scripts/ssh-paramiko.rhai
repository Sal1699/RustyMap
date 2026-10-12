// @name: ssh-paramiko
// @description: Paramiko (Python SSH) endpoint
// @category: ssh
// @severity: info
// @tags: ssh, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 22 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let b = svc.banner;
    if type_of(b) != "string" { continue; }
    if b.to_lower().contains("paramiko") {
        findings.push(#{ severity: "info", port: 22, message: `Paramiko (Python SSH) endpoint: ${b.trim()}` });
    }
}
