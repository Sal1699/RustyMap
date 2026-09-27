// @name: uptime-kuma-exposed
// @description: Detect an Uptime Kuma monitoring dashboard
// @category: monitoring
// @severity: info
// @tags: monitoring, uptime-kuma
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 3001 && p.port != 80 && p.port != 443 { continue; }
    let scheme = if p.port == 443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/`, 3000);
    if resp.status == 0 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if body.index_of("Uptime Kuma") >= 0 {
        findings.push(#{
            severity: "info",
            port: p.port,
            message: "Uptime Kuma dashboard reachable — status pages may leak internal hostnames/topology"
        });
    }
}
