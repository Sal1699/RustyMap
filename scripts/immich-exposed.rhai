// @name: immich-exposed
// @description: Detect an Immich self-hosted photo server
// @category: media
// @severity: info
// @tags: immich, media
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 2283 && p.port != 80 && p.port != 443 { continue; }
    let scheme = if p.port == 443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/api/server/ping`, 3000);
    if resp.status == 0 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if body.index_of("pong") >= 0 {
        findings.push(#{
            severity: "info",
            port: p.port,
            message: "Immich photo server reachable — confirm registration is disabled and it sits behind auth"
        });
    }
}
