// Flag HTTP endpoints likely serving GraphQL — introspection is on by
// default and leaks the full schema. We only reason on what HTTP banner
// already shows; the operator should follow up with a `__schema` query.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 && p.port != 8443 && p.port != 4000 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let banner = svc.banner;
    if type_of(banner) != "string" { continue; }
    let lo = banner.to_lower();
    if lo.contains("graphql") || lo.contains("apollo") || lo.contains("hasura") {
        findings.push(#{
            severity: "medium",
            port: p.port,
            message: "GraphQL surface detected — disable introspection in production (POST __schema otherwise leaks types)"
        });
    }
}
