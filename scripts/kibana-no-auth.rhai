// Flag Kibana running without xpack.security — full ES read access.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5601 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let prod = svc.product;
    if type_of(prod) != "string" { continue; }
    if prod.to_lower().contains("kibana") {
        findings.push(#{
            severity: "high",
            port: 5601,
            message: "Kibana on 5601 — verify xpack.security.enabled=true"
        });
    }
}
