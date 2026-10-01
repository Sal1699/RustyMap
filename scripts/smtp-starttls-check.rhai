// @name: smtp-starttls-check
// @description: Flag SMTP submission that does not advertise STARTTLS
// @category: mail
// @severity: low
// @tags: smtp, starttls, cleartext, mail
// @author: rustymap
// After EHLO an SMTP server lists its extensions. If STARTTLS is absent on
// a submission/relay port, credentials and mail can be sent in clear text.
// We only act when EHLO actually succeeded (a 250 reply) to avoid flagging
// a read that caught only the 220 greeting.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 25 && p.port != 587 { continue; }
    let resp = tcp_send(host.ip, p.port, "EHLO rustymap.local\r\n", 3500);
    let low = resp.to_lower();
    if low.index_of("250") < 0 { continue; }
    if low.index_of("starttls") < 0 {
        findings.push(#{
            severity: "low",
            port: p.port,
            message: "SMTP does not advertise STARTTLS — mail/credentials can be sent in clear text"
        });
    }
}
