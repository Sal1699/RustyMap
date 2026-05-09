// @name: jwt-alg-none
// @description: Flag JWT tokens visible in HTTP banners with weak/none alg
// @category: web
// @severity: high
// @tags: jwt, auth, owasp-a07
// @cve: CVE-2018-1000136, CVE-2018-1000531
// @references: https://jwt.io/, https://datatracker.ietf.org/doc/html/rfc7519
//
// JWT format: <base64url-header>.<base64url-payload>.<sig>. We detect the
// header part containing "alg":"none" (server may accept unsigned tokens)
// or "HS256" with a public key context (asymmetric algos are stronger).
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 && p.port != 8443 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let banner = svc.banner;
    if type_of(banner) != "string" { continue; }
    let lo = banner.to_lower();
    // Look for JWT in Authorization or Set-Cookie headers
    if lo.contains("bearer ey") || lo.contains("=ey") {
        // Extremely common JWT header prefixes when base64-decoded:
        //   {"alg":"none"  → eyJhbGciOiJub25lI
        //   {"alg":"HS256" → eyJhbGciOiJIUzI1NiI
        //   {"alg":"RS256" → eyJhbGciOiJSUzI1NiI
        if banner.contains("eyJhbGciOiJub25lI") || banner.contains("eyJhbGciOm5vbmU") {
            findings.push(#{
                severity: "critical",
                port: p.port,
                message: "JWT visible with alg=none — server accepts unsigned tokens"
            });
        } else if banner.contains("eyJhbGciOiJIUzI1NiI") {
            findings.push(#{
                severity: "low",
                port: p.port,
                message: "JWT with alg=HS256 — verify server key is rotated and ≥256 bits"
            });
        } else if banner.contains("ey") {
            findings.push(#{
                severity: "info",
                port: p.port,
                message: "JWT visible in HTTP — verify TLS-only transport and short expiry"
            });
        }
    }
}
