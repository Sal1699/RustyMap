// Flag VNC — RFB protocol allows "type 1" (no auth) by default in many
// embedded deployments and the password version (type 2) uses an 8-char
// truncated DES key, brute-forceable.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5900 && p.port != 5901 && p.port != 5902 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let prod = svc.product;
    if type_of(prod) != "string" { continue; }
    if prod.to_lower().contains("vnc") || prod.to_lower().contains("rfb") {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: "VNC reachable — disable type-1 (no auth) and prefer SSH-tunneled access"
        });
    }
}
