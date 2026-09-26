// @name: smtp-banner
// @description: Read the SMTP 220 greeting and name the MTA
// @category: mail
// @severity: info
// @tags: smtp, fingerprint
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 25 && p.port != 587 && p.port != 465 { continue; }
    let resp = tcp_send(host.ip, p.port, "", 2500);
    if resp.index_of("220") < 0 { continue; }
    let line = resp.trim();
    if len(line) > 160 { line = line.sub_string(0, 160) + "…"; }
    let mta = if line.to_lower().index_of("postfix") >= 0 { "Postfix" }
        else if line.to_lower().index_of("exim") >= 0 { "Exim" }
        else if line.to_lower().index_of("sendmail") >= 0 { "Sendmail" }
        else if line.to_lower().index_of("microsoft") >= 0 { "Microsoft ESMTP" }
        else { "unknown MTA" };
    findings.push(#{
        severity: "info",
        port: p.port,
        message: `SMTP greeting (${mta}): ${line}`
    });
}
