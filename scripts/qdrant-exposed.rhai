// @name: qdrant-exposed
// @description: Detect an unauthenticated Qdrant vector database
// @category: database
// @severity: high
// @tags: vector-db, qdrant, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 6333 && p.port != 80 && p.port != 443 { continue; }
    let scheme = if p.port == 443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/collections`, 3000);
    if resp.status == 0 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if body.index_of("\"result\"") >= 0 && body.index_of("collections") >= 0 {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: "Qdrant vector DB reachable without an API key — embeddings/collections are readable"
        });
    }
}
