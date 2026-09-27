// @name: weaviate-exposed
// @description: Detect an unauthenticated Weaviate vector database
// @category: database
// @severity: high
// @tags: vector-db, weaviate, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8080 && p.port != 80 && p.port != 443 { continue; }
    let scheme = if p.port == 443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/v1/meta`, 3000);
    if resp.status != 200 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if body.index_of("version") >= 0 && (body.index_of("weaviate") >= 0 || body.index_of("hostname") >= 0) {
        let ver = regex_capture("(?i)\"version\"\\s*:\\s*\"([\\d.]+)\"", body);
        findings.push(#{
            severity: "high",
            port: p.port,
            message: `Weaviate vector DB exposed without auth (version ${ver})`
        });
    }
}
