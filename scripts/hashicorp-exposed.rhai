// Flag HashiCorp services exposed on the network. Vault initial-token
// race, Consul ACL bypass, Nomad raw-exec are all classic incidents.
for p in host.ports {
    if p.state != "open" { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let prod = svc.product;
    if type_of(prod) != "string" { continue; }
    let lo = prod.to_lower();
    if lo.contains("vault") {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: "HashiCorp Vault reachable — verify it's initialized + unsealed + audit-logged + restricted by ACL"
        });
    } else if lo.contains("consul") {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: "HashiCorp Consul reachable — verify default_policy=deny in acl block + bootstrap completed"
        });
    } else if lo.contains("nomad") {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: "HashiCorp Nomad reachable — disable raw-exec / privileged docker if not needed"
        });
    }
}
