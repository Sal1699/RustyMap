// @name: ftp-pureftpd-detect
// @description: Pure-FTPd server
// @category: ftp
// @severity: info
// @tags: ftp, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 21 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let b = svc.banner;
    if type_of(b) != "string" { continue; }
    if b.to_lower().contains("pure-ftpd") {
        findings.push(#{ severity: "info", port: 21, message: `Pure-FTPd server: ${b.trim()}` });
    }
}
