// @name: arangodb-exposed
// @description: Detect an exposed ArangoDB server and its version
// @category: database
// @severity: medium
// @tags: arangodb, database, exposure
// @author: rustymap
// ArangoDB's /_api/version endpoint responds unauthenticated when the
// server runs with authentication disabled (--server.authentication false),
// a common demo/dev misconfiguration that exposes the whole datastore.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8529 { continue; }
    let resp = http_get(`http://${host.ip}:${p.port}/_api/version`, 3000);
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if resp.status == 200 && body.index_of("arango") >= 0 {
        let ver = regex_capture("\"version\"\\s*:\\s*\"([^\"]+)\"", body);
        findings.push(#{
            severity: "medium",
            port: p.port,
            message: `ArangoDB reachable with authentication disabled (version ${ver})`
        });
    } else if resp.status == 401 {
        findings.push(#{
            severity: "info",
            port: p.port,
            message: "ArangoDB detected (authentication enabled)"
        });
    }
}
