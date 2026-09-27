// @name: typesense-exposed
// @description: Detect a Typesense search server and its health state
// @category: database
// @severity: medium
// @tags: search, typesense, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8108 { continue; }
    let resp = http_get(`http://${host.ip}:${p.port}/health`, 3000);
    if resp.status == 0 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if body.index_of("\"ok\"") >= 0 {
        findings.push(#{ severity: "medium", port: 8108, message: "Typesense reachable — confirm the API key is required (unkeyed nodes allow full search/index access)" });
    }
}
