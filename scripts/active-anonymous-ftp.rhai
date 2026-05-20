// @name: active-anonymous-ftp
// @description: Active probe: confirm anonymous FTP login allowed
// @category: recon
// @severity: high
// @tags: ftp, anonymous
// Active probe: try FTP USER anonymous + PASS anonymous@.
// Reads server greeting first to confirm we hit FTP, then attempts
// the login. 230 = logged in, 530 = denied.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 21 && p.port != 990 && p.port != 2121 { continue; }
    let greeting = tcp_send(host.ip, p.port, "", 1500);
    if !greeting.starts_with("220") { continue; }
    let login = tcp_send(host.ip, p.port, "USER anonymous\r\nPASS anonymous@\r\n", 2500);
    if login.contains("230") {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: "FTP anonymous login accepted (USER anonymous, PASS anonymous@)"
        });
    } else if login.contains("331") || login.contains("530") {
        findings.push(#{
            severity: "info",
            port: p.port,
            message: "FTP rejects anonymous (331/530 — auth required)"
        });
    }
}
