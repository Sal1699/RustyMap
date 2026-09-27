// @name: redpanda-admin-exposed
// @description: Detect an exposed Redpanda admin API
// @category: streaming
// @severity: medium
// @tags: redpanda, kafka, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 9644 { continue; }
    let resp = http_get(`http://${host.ip}:${p.port}/v1/status/ready`, 3000);
    if resp.status == 0 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body.to_lower() } else { "" };
    if resp.status == 200 || body.index_of("ready") >= 0 {
        findings.push(#{ severity: "medium", port: 9644, message: "Redpanda admin API reachable — cluster config/brokers exposed; restrict the admin listener" });
    }
}
