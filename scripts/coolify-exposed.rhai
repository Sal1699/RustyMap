// @name: coolify-exposed
// @description: Detect a Coolify self-hosted PaaS control panel
// @category: paas
// @severity: medium
// @tags: coolify, paas, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8000 && p.port != 80 && p.port != 443 { continue; }
    let scheme = if p.port == 443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/`, 3000);
    if resp.status == 0 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if body.index_of("Coolify") >= 0 {
        findings.push(#{ severity: "medium", port: p.port, message: "Coolify control panel exposed — it can deploy/destroy apps & holds infra credentials; lock it down" });
    }
}
