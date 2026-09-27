// @name: jellyfin-exposed
// @description: Detect a Jellyfin media server via its public info endpoint
// @category: media
// @severity: info
// @tags: media, jellyfin
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8096 && p.port != 80 && p.port != 443 { continue; }
    let scheme = if p.port == 443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/System/Info/Public`, 3000);
    if resp.status != 200 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if body.index_of("Jellyfin") >= 0 || body.index_of("ServerName") >= 0 {
        let ver = regex_capture("(?i)\"Version\"\\s*:\\s*\"([\\d.]+)\"", body);
        findings.push(#{
            severity: "info",
            port: p.port,
            message: `Jellyfin media server (version ${ver}) — public server info is exposed`
        });
    }
}
