// Flag modern identity providers exposed to the public internet —
// each carries known operator pitfalls (default admin, registration on,
// SSO trust to all clients, etc.).
for p in host.ports {
    if p.state != "open" { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let prod = svc.product;
    if type_of(prod) != "string" { continue; }
    let lo = prod.to_lower();
    if lo.contains("authelia") {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: "Authelia reachable — verify config.yml authentication_backend + access_control rules"
        });
    } else if lo.contains("authentik") {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: "Authentik reachable — verify default akadmin password was changed at first run"
        });
    } else if lo.contains("keycloak") {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: "Keycloak reachable — restrict /admin/ to mgmt network, disable open registration"
        });
    } else if lo.contains("zitadel") {
        findings.push(#{
            severity: "medium",
            port: p.port,
            message: "ZITADEL reachable — verify org/project IAM is locked down"
        });
    }
}
