// @name: signoz-exposed
// @description: Detect a SigNoz observability UI
// @category: monitoring
// @severity: info
// @tags: signoz, observability
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 3301 && p.port != 3000 && p.port != 8080 { continue; }
    let resp = http_get(`http://${host.ip}:${p.port}/`, 3000);
    if resp.status == 0 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if body.index_of("SigNoz") >= 0 {
        findings.push(#{ severity: "info", port: p.port, message: "SigNoz UI reachable — traces/metrics/logs may expose internal topology; require login" });
    }
}
