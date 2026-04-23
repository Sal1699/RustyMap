// Flag SSH banners advertising versions known to have pre-auth issues.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 22 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let banner = svc.banner;
    if type_of(banner) != "string" { continue; }

    // regreSSHion (CVE-2024-6387) — OpenSSH 8.5p1 .. 9.7p1
    if banner.contains("OpenSSH_8.5") || banner.contains("OpenSSH_8.6")
        || banner.contains("OpenSSH_8.7") || banner.contains("OpenSSH_8.8")
        || banner.contains("OpenSSH_8.9") || banner.contains("OpenSSH_9.0")
        || banner.contains("OpenSSH_9.1") || banner.contains("OpenSSH_9.2")
        || banner.contains("OpenSSH_9.3") || banner.contains("OpenSSH_9.4")
        || banner.contains("OpenSSH_9.5") || banner.contains("OpenSSH_9.6")
        || banner.contains("OpenSSH_9.7") {
        findings.push(#{
            severity: "critical",
            port: 22,
            message: `regreSSHion candidate (${banner}) — patch to OpenSSH 9.8+`
        });
    }
    // Username enumeration era (≤7.6)
    else if banner.contains("OpenSSH_7.0") || banner.contains("OpenSSH_7.1")
        || banner.contains("OpenSSH_7.2") || banner.contains("OpenSSH_7.3")
        || banner.contains("OpenSSH_7.4") || banner.contains("OpenSSH_7.5")
        || banner.contains("OpenSSH_7.6") {
        findings.push(#{
            severity: "medium",
            port: 22,
            message: `OpenSSH ≤7.6 (${banner}) — vulnerable to username enumeration`
        });
    }
    // Anything pre-7 is just old
    else if banner.contains("OpenSSH_4.") || banner.contains("OpenSSH_5.") || banner.contains("OpenSSH_6.") {
        findings.push(#{
            severity: "high",
            port: 22,
            message: `Very old SSH (${banner}) — multiple known issues, upgrade`
        });
    }
}
