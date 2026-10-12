// @name: exposed-management
// @description: Flag ports commonly used by management planes (verify the service)
// @category: exposure
// @severity: low
// @tags: management, exposure
// Port-based HINT only: these ports are COMMONLY management interfaces, but
// many are shared (9000 = SonarQube/Portainer/PHP-FPM/cameras; 3000 = Grafana/
// dev). We therefore flag the exposure as a low-severity hint and name the
// typical service with "commonly", instead of asserting it — a port number is
// not a service (lab v0.87.0 BUG-3: :9000 on an IP camera was mislabelled
// "SonarQube"). When -sV identified a product, we fold it into the message.
fn label_for(p) {
    if p == 4444 { return "Metasploit handler"; }
    if p == 5985 { return "WinRM (HTTP)"; }
    if p == 5986 { return "WinRM (HTTPS)"; }
    if p == 7001 { return "Oracle WebLogic admin"; }
    if p == 7002 { return "Oracle WebLogic admin (TLS)"; }
    if p == 9990 { return "JBoss/WildFly mgmt"; }
    if p == 4848 { return "GlassFish admin"; }
    if p == 8161 { return "ActiveMQ admin"; }
    if p == 9000 { return "SonarQube/Portainer/PHP-FPM"; }
    if p == 9090 { return "Prometheus/Cockpit"; }
    if p == 3000 { return "Grafana/dev server"; }
    if p == 8500 { return "HashiCorp Consul"; }
    if p == 4646 { return "HashiCorp Nomad"; }
    if p == 8200 { return "HashiCorp Vault"; }
    if p == 5601 { return "Kibana"; }
    return "";
}
for p in host.ports {
    if p.state != "open" { continue; }
    let lbl = label_for(p.port);
    if lbl == "" { continue; }
    // Fold in the -sV product when known, for a sharper message.
    let prod = "";
    let svc = p.service;
    if type_of(svc) == "map" && type_of(svc.product) == "string" { prod = svc.product; }
    let msg = if prod != "" {
        `port ${p.port} open — ${prod} (commonly ${lbl}); keep mgmt planes on a separate VLAN`
    } else {
        `port ${p.port} open — commonly ${lbl}; verify the service and keep mgmt planes off untrusted nets`
    };
    findings.push(#{ severity: "low", port: p.port, message: msg });
}
