// @name: cockpit-exposed
// @description: Cockpit/Prometheus-class admin on 9090
// @category: mgmt
// @severity: low
// @tags: mgmt, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 9090 { continue; }
    findings.push(#{ severity: "low", port: 9090, message: "Cockpit/Prometheus-class admin on 9090" });
}
