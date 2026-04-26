// Flag exposed Elasticsearch / Kibana clusters reachable without auth.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 9200 && p.port != 9300 && p.port != 5601 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let prod = svc.product;
    if type_of(prod) != "string" { continue; }
    let lo = prod.to_lower();
    if lo.contains("elasticsearch") {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: "Elasticsearch reachable — verify xpack security is on (cluster data otherwise readable)"
        });
    } else if lo.contains("kibana") {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: "Kibana reachable — verify auth (anonymous access exposes saved objects)"
        });
    }
}
