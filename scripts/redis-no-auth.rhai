// Flag exposed Redis instances. Reasons over service info populated by
// the built-in Redis probe — banner usually contains "Redis" without a
// "NOAUTH" hint, meaning anonymous commands are accepted.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 6379 && p.port != 6380 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let prod = svc.product;
    if type_of(prod) != "string" { continue; }
    if !prod.to_lower().contains("redis") { continue; }
    let banner = svc.banner;
    let banner_lo = if type_of(banner) == "string" { banner.to_lower() } else { "" };
    if !banner_lo.contains("noauth") && !banner_lo.contains("authentication required") {
        findings.push(#{
            severity: "critical",
            port: p.port,
            message: "Redis appears to accept commands without authentication — set requirepass or bind to localhost"
        });
    }
}
