// Flag Jenkins instance — frequent target of anonymous job execution
// when "anyone can do anything" is left as the default auth strategy.
for p in host.ports {
    if p.state != "open" { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let prod = svc.product;
    if type_of(prod) != "string" { continue; }
    if prod.to_lower().contains("jenkins") {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: "Jenkins reachable — verify the security realm and authorization strategy (avoid 'anyone can do anything')"
        });
    }
}
