// @name: mongo-express-exposed
// @description: Detect an exposed Mongo Express web admin UI
// @category: database
// @severity: high
// @tags: mongodb, mongo-express, admin-ui, exposure
// @author: rustymap
// Mongo Express is a web admin panel for MongoDB. When reachable without
// basic-auth it grants full read/write over every database from the browser;
// several releases also shipped an RCE (CVE-2019-10758).
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8081 && p.port != 8082 && p.port != 80 { continue; }
    let resp = http_get(`http://${host.ip}:${p.port}/`, 3000);
    if resp.status != 200 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    let low = body.to_lower();
    if low.index_of("mongo express") < 0 && low.index_of("mongoexpress") < 0 { continue; }
    findings.push(#{
        severity: "high",
        port: p.port,
        message: "Mongo Express admin UI reachable without authentication — full MongoDB access"
    });
}
