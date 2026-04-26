// Flag LDAP/LDAPS reachable — verify auth & null-bind disabled.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 389 && p.port != 636 && p.port != 3268 && p.port != 3269 { continue; }
    let what = if p.port == 389 || p.port == 3268 { "LDAP (cleartext)" } else { "LDAPS" };
    let sev = if p.port == 389 || p.port == 3268 { "medium" } else { "low" };
    findings.push(#{
        severity: sev,
        port: p.port,
        message: `${what} on ${p.port} — test anonymous bind with ldapsearch -x -h <host> -b ""`
    });
}
