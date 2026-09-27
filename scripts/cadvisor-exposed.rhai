// @name: cadvisor-exposed
// @description: Detect an exposed cAdvisor container-metrics UI
// @category: monitoring
// @severity: medium
// @tags: cadvisor, containers, info-leak
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8080 { continue; }
    let resp = http_get(`http://${host.ip}:${p.port}/metrics`, 3000);
    if resp.status != 200 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if body.index_of("container_cpu_usage_seconds_total") >= 0 || body.index_of("cadvisor_version_info") >= 0 {
        findings.push(#{ severity: "medium", port: 8080, message: "cAdvisor metrics exposed — leaks running containers, images and resource usage" });
    }
}
