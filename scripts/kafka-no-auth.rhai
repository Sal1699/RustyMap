// Flag Kafka brokers — default deployments have no auth on 9092 plain.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 9092 && p.port != 9093 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let prod = svc.product;
    let prod_lo = if type_of(prod) == "string" { prod.to_lower() } else { "" };
    if prod_lo.contains("kafka") {
        let sev = if p.port == 9092 { "high" } else { "medium" };
        findings.push(#{
            severity: sev,
            port: p.port,
            message: "Apache Kafka broker reachable — verify SASL/SSL auth (PLAIN listener allows arbitrary publish/consume)"
        });
    }
}
