// @name: meilisearch-exposed
// @description: Detect a Meilisearch instance and whether it needs a key
// @category: database
// @severity: medium
// @tags: search, meilisearch, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 7700 && p.port != 80 && p.port != 443 { continue; }
    let scheme = if p.port == 443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/health`, 3000);
    if resp.status == 0 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    let hdr = if type_of(resp.headers) == "string" { resp.headers.to_lower() } else { "" };
    if body.index_of("\"status\"") >= 0 && (hdr.index_of("meilisearch") >= 0 || body.index_of("available") >= 0) {
        let sev = if resp.status == 200 { "medium" } else { "info" };
        findings.push(#{
            severity: sev,
            port: p.port,
            message: "Meilisearch reachable — verify a master key is set (unkeyed instances allow full index access)"
        });
    }
}
