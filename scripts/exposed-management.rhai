// Flag mgmt-plane interfaces that historically should NOT be on the WAN.
fn label_for(p) {
    if p == 4444 { return "Metasploit handler"; }
    if p == 5985 { return "WinRM (HTTP)"; }
    if p == 5986 { return "WinRM (HTTPS)"; }
    if p == 7001 { return "Oracle WebLogic admin"; }
    if p == 7002 { return "Oracle WebLogic admin (TLS)"; }
    if p == 9990 { return "JBoss/WildFly mgmt"; }
    if p == 4848 { return "GlassFish admin"; }
    if p == 8161 { return "ActiveMQ admin"; }
    if p == 9000 { return "SonarQube / Portainer"; }
    if p == 9090 { return "Prometheus / Cockpit"; }
    if p == 3000 { return "Grafana / common dev port"; }
    if p == 8500 { return "HashiCorp Consul"; }
    if p == 4646 { return "HashiCorp Nomad"; }
    if p == 8200 { return "HashiCorp Vault"; }
    if p == 5601 { return "Kibana"; }
    return "";
}
for p in host.ports {
    if p.state != "open" { continue; }
    let lbl = label_for(p.port);
    if lbl != "" {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: `${lbl} on ${p.port} — management plane should be on a separate VLAN`
        });
    }
}
