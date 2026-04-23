// Flag TLS endpoints negotiating deprecated protocol versions.
for p in host.ports {
    if p.state != "open" { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let tls = svc.tls;
    if type_of(tls) != "map" { continue; }
    let neg = tls.negotiated;
    if type_of(neg) != "string" { continue; }

    if neg.contains("1.0") || neg.contains("1.1") {
        findings.push(#{
            severity: "medium",
            port: p.port,
            message: `TLS endpoint negotiated ${neg} — disable TLS 1.0/1.1`
        });
    }
}
