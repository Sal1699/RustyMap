// @name: couchbase-exposed
// @description: Detect an exposed Couchbase management interface
// @category: database
// @severity: medium
// @tags: couchbase, nosql, exposure
// @author: rustymap
// Couchbase's REST management port (8091) answers /pools with the product
// name and cluster version before authentication. An exposed management
// plane is a stepping stone to the data and often ships default creds.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8091 && p.port != 8092 { continue; }
    let resp = http_get(`http://${host.ip}:${p.port}/pools`, 3000);
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if body.to_lower().index_of("couchbase") < 0 && body.index_of("implementationVersion") < 0 { continue; }
    let ver = regex_capture("\"implementationVersion\"\\s*:\\s*\"([^\"]+)\"", body);
    findings.push(#{
        severity: "medium",
        port: p.port,
        message: `Couchbase management interface exposed (version ${ver})`
    });
}
