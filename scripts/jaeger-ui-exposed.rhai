// @name: jaeger-ui-exposed
// @description: Detect an exposed Jaeger tracing UI
// @category: monitoring
// @severity: medium
// @tags: jaeger, tracing, info-leak
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 16686 { continue; }
    let resp = http_get(`http://${host.ip}:${p.port}/search`, 3000);
    if resp.status == 0 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if body.index_of("Jaeger UI") >= 0 || body.index_of("jaeger") >= 0 {
        findings.push(#{ severity: "medium", port: 16686, message: "Jaeger UI exposed — traces leak internal service names, URLs and payload fragments" });
    }
}
