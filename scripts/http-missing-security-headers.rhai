// Flag HTTP responses missing common security headers (HSTS, CSP, XFO).
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 && p.port != 8443 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let banner = svc.banner;
    if type_of(banner) != "string" { continue; }
    let lo = banner.to_lower();
    let missing = [];
    if !lo.contains("strict-transport-security") && p.port == 443 {
        missing.push("HSTS");
    }
    if !lo.contains("content-security-policy") {
        missing.push("CSP");
    }
    if !lo.contains("x-frame-options") && !lo.contains("frame-ancestors") {
        missing.push("XFO/frame-ancestors");
    }
    if !lo.contains("x-content-type-options") {
        missing.push("X-Content-Type-Options");
    }
    if missing.len() >= 3 {
        findings.push(#{
            severity: "low",
            port: p.port,
            message: `Missing security headers: ${missing}`
        });
    }
}
