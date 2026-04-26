// Flag MongoDB without auth (port responds but banner says no auth required).
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 27017 && p.port != 27018 && p.port != 27019 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let prod = svc.product;
    if type_of(prod) != "string" { continue; }
    if prod.to_lower().contains("mongo") {
        findings.push(#{
            severity: "critical",
            port: p.port,
            message: "MongoDB reachable — verify --auth is enabled (default deployments allow anonymous reads/writes)"
        });
    }
}
