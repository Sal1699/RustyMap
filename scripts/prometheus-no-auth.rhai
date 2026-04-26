// Flag Prometheus / node_exporter / pushgateway exposed without auth.
// node_exporter on 9100 leaks process list, mounted FS, kernel ver.
fn label(p) {
    if p == 9090 { return "Prometheus server"; }
    if p == 9091 { return "Prometheus pushgateway"; }
    if p == 9100 { return "node_exporter"; }
    if p == 9115 { return "blackbox_exporter"; }
    if p == 9182 { return "windows_exporter"; }
    if p == 9300 { return "cadvisor"; }
    return "";
}
for p in host.ports {
    if p.state != "open" { continue; }
    let lbl = label(p.port);
    if lbl != "" {
        findings.push(#{
            severity: "medium",
            port: p.port,
            message: `${lbl} on ${p.port} — expose only to monitoring VLAN (leaks system internals)`
        });
    }
}
