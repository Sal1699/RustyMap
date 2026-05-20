// @name: cookie-flags-audit
// @description: Audit HTTP cookie flags (Secure / HttpOnly / SameSite)
// @category: web
// @severity: low
// @tags: http, cookies
// Flag Set-Cookie headers missing Secure / HttpOnly / SameSite.
// Reasons over the HTTP banner already collected by vendor_probe.
fn audit(banner, port) {
    let lo = banner.to_lower();
    let lines = banner.split("\r\n");
    for line in lines {
        let llo = line.to_lower();
        if !llo.starts_with("set-cookie:") { continue; }
        let issues = [];
        if !llo.contains("secure") {
            issues.push("Secure missing");
        }
        if !llo.contains("httponly") {
            issues.push("HttpOnly missing");
        }
        if !llo.contains("samesite") {
            issues.push("SameSite missing");
        }
        if issues.len() >= 2 {
            findings.push(#{
                severity: "low",
                port: port,
                message: `Cookie flags: ${issues}`
            });
        }
    }
}

for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 && p.port != 8443 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let banner = svc.banner;
    if type_of(banner) != "string" { continue; }
    audit(banner, p.port);
}
