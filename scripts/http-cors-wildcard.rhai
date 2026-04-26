// Flag HTTP services likely vulnerable to CORS misconfig: ACAO=*
// combined with ACAC=true would let any site read responses.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 && p.port != 8443 && p.port != 8000 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let banner = svc.banner;
    if type_of(banner) != "string" { continue; }
    let lo = banner.to_lower();
    if lo.contains("access-control-allow-origin: *") {
        let sev = if lo.contains("access-control-allow-credentials: true") {
            "critical"
        } else {
            "low"
        };
        findings.push(#{
            severity: sev,
            port: p.port,
            message: "CORS Access-Control-Allow-Origin: * — verify combination with ACA-Credentials"
        });
    }
}
