// Flag Docker daemon API exposed without TLS — full container takeover.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port == 2375 {
        findings.push(#{
            severity: "critical",
            port: 2375,
            message: "Docker daemon API on 2375 (cleartext) — full container/host RCE if reachable"
        });
    } else if p.port == 2376 {
        findings.push(#{
            severity: "high",
            port: 2376,
            message: "Docker daemon API on 2376 — verify TLS client cert authentication"
        });
    }
}
