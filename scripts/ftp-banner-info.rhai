// @name: ftp-banner-info
// @description: Grab the FTP 220 greeting and name the server software
// @category: ftp
// @severity: info
// @tags: ftp, fingerprint
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 21 && p.port != 2121 { continue; }
    let resp = tcp_send(host.ip, p.port, "", 2500);
    if resp.index_of("220") < 0 { continue; }
    let line = resp.trim();
    if len(line) > 160 { line = line.sub_string(0, 160) + "…"; }
    // Flag the well-known bounce-capable / vulnerable banners.
    let sev = if line.to_lower().index_of("wu-ftpd") >= 0
        || line.to_lower().index_of("proftpd 1.3.3") >= 0 { "medium" } else { "info" };
    findings.push(#{
        severity: sev,
        port: p.port,
        message: `FTP banner: ${line}`
    });
}
