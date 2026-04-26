// Flag Portainer (9000/9443) — Docker/k8s/swarm UI; setup-by-first-visit
// allows the first reachable user to claim admin if not initialized.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 9000 && p.port != 9443 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let prod = svc.product;
    if type_of(prod) != "string" { continue; }
    if prod.to_lower().contains("portainer") {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: "Portainer reachable — verify the admin user has been initialized (first-visit claims admin if not)"
        });
    }
}
