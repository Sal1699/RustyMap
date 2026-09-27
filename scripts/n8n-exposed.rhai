// @name: n8n-exposed
// @description: Detect an n8n workflow-automation instance
// @category: automation
// @severity: medium
// @tags: n8n, automation, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5678 && p.port != 80 && p.port != 443 { continue; }
    let scheme = if p.port == 443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/`, 3000);
    if resp.status == 0 { continue; }
    let hdr = if type_of(resp.headers) == "string" { resp.headers.to_lower() } else { "" };
    let body = if type_of(resp.body) == "string" { resp.body.to_lower() } else { "" };
    if hdr.index_of("n8n") >= 0 || body.index_of("n8n") >= 0 {
        findings.push(#{
            severity: "medium",
            port: p.port,
            message: "n8n exposed — workflows can hold credentials/webhooks; confirm authentication is enabled"
        });
    }
}
