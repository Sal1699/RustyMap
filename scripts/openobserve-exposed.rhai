// @name: openobserve-exposed
// @description: Detect an OpenObserve observability instance
// @category: monitoring
// @severity: info
// @tags: observability, openobserve
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5080 && p.port != 80 && p.port != 443 { continue; }
    let scheme = if p.port == 443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/web/`, 3000);
    if resp.status == 0 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body.to_lower() } else { "" };
    let hdr = if type_of(resp.headers) == "string" { resp.headers.to_lower() } else { "" };
    if body.index_of("openobserve") >= 0 || hdr.index_of("openobserve") >= 0 {
        findings.push(#{
            severity: "info",
            port: p.port,
            message: "OpenObserve reachable — logs/traces may contain sensitive data; require login"
        });
    }
}
