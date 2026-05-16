// Active probe: Apache CouchDB. Pre-3.0 "admin party" instances allow
// any operation. Even on 3.x, an exposed _all_dbs to anonymous users
// is a known misconfiguration.
// @name couchdb-no-auth
// @description Detect CouchDB instances readable without authentication
// @category vuln
// @severity high
// @tags couchdb database
// @author rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5984 && p.port != 6984 { continue; }
    let scheme = if p.port == 6984 { "https" } else { "http" };
    let base = `${scheme}://${host.ip}:${p.port}`;
    let root = http_get(`${base}/`, 2500);
    if root.status != 200 || !regex_match(`"couchdb":\\s*"Welcome"`, root.body) { continue; }
    let ver = regex_capture(`"version":"([^"]+)"`, root.body);
    let dbs = http_get(`${base}/_all_dbs`, 2500);
    if dbs.status == 200 && dbs.body.starts_with("[") {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: `CouchDB ${ver} _all_dbs listable anonymously`
        });
    }
}
