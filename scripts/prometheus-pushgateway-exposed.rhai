// Active probe: Prometheus Pushgateway /metrics endpoint. Pushgateway
// has no native auth; if reachable it lets anyone publish (or read)
// arbitrary metrics, including label-injection attacks into the parent
// Prometheus.
// @name prometheus-pushgateway-exposed
// @description Detect Prometheus Pushgateway accepting unauthenticated metric pushes
// @category vuln
// @severity high
// @tags prometheus monitoring pushgateway
// @author rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 9091 { continue; }
    let url = `http://${host.ip}:${p.port}/metrics`;
    let resp = http_get(url, 3000);
    if resp.status != 200 { continue; }
    if regex_match("pushgateway_build_info", resp.body) {
        let ver = regex_capture(`version="([^"]+)"`, resp.body);
        findings.push(#{
            severity: "high",
            port: p.port,
            message: `Prometheus Pushgateway ${ver} exposed without auth — metric injection risk`
        });
    }
}
