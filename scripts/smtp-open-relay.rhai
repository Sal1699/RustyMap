// Flag SMTP / submission ports — historical open-relay risk.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 25 && p.port != 465 && p.port != 587 && p.port != 2525 { continue; }
    let svc = p.service;
    let banner = if type_of(svc) == "map" {
        let b = svc.banner;
        if type_of(b) == "string" { b.to_lower() } else { "" }
    } else { "" };
    let sev = if p.port == 25 { "medium" } else { "low" };
    let note = if banner.contains("postfix") || banner.contains("exim") || banner.contains("sendmail") {
        ` (${if banner.contains("postfix") { "Postfix" } else if banner.contains("exim") { "Exim" } else { "Sendmail" }})`
    } else { "" };
    findings.push(#{
        severity: sev,
        port: p.port,
        message: `SMTP reachable${note} — test for open relay with swaks --to user@external --from user@external`
    });
}
