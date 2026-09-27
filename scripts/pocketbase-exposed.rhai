// @name: pocketbase-exposed
// @description: Detect a PocketBase backend and its admin setup state
// @category: backend
// @severity: medium
// @tags: baas, pocketbase, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8090 && p.port != 80 && p.port != 443 { continue; }
    let scheme = if p.port == 443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/api/health`, 3000);
    if resp.status == 0 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if body.index_of("\"code\"") >= 0 && body.index_of("healthy") >= 0 {
        findings.push(#{
            severity: "medium",
            port: p.port,
            message: "PocketBase backend reachable — ensure the admin account is created and the API rules are locked down"
        });
    }
}
