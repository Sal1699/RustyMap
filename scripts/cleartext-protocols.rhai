// Flag classic cleartext-credential services exposed on the wire.
fn label_for(p) {
    if p == 21 { return "FTP"; }
    if p == 23 { return "Telnet"; }
    if p == 69 { return "TFTP"; }
    if p == 110 { return "POP3"; }
    if p == 143 { return "IMAP"; }
    if p == 389 { return "LDAP"; }
    if p == 513 { return "rlogin"; }
    if p == 514 { return "rsh"; }
    if p == 548 { return "AFP"; }
    if p == 1521 { return "Oracle TNS"; }
    if p == 2049 { return "NFS"; }
    if p == 5900 { return "VNC"; }
    return "";
}
for p in host.ports {
    if p.state != "open" { continue; }
    let lbl = label_for(p.port);
    if lbl != "" {
        findings.push(#{
            severity: "medium",
            port: p.port,
            message: `${lbl} cleartext service exposed — prefer the TLS variant`
        });
    }
}
