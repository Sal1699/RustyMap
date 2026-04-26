// Flag FTP service banners that suggest anonymous login is allowed.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 21 && p.port != 990 && p.port != 2121 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let banner = svc.banner;
    if type_of(banner) != "string" { continue; }
    let lo = banner.to_lower();
    if lo.contains("anonymous") || lo.contains("ftp ready") || lo.contains("vsftpd") || lo.contains("pure-ftpd") {
        findings.push(#{
            severity: "medium",
            port: p.port,
            message: `FTP banner mentions ${banner.sub_string(0, 60)} — try anonymous login`
        });
    }
}
