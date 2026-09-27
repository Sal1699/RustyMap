// @name: http-phpmyadmin
// @description: Detect an exposed phpMyAdmin login
// @category: http
// @severity: medium
// @tags: http, phpmyadmin, database, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 { continue; }
    let scheme = if p.port == 443 { "https" } else { "http" };
    for path in ["/phpmyadmin/", "/pma/", "/phpMyAdmin/"] {
        let resp = http_get(`${scheme}://${host.ip}:${p.port}${path}`, 3000);
        if resp.status != 200 { continue; }
        let body = if type_of(resp.body) == "string" { resp.body } else { "" };
        if body.index_of("phpMyAdmin") >= 0 {
            findings.push(#{
                severity: "medium",
                port: p.port,
                message: `phpMyAdmin exposed at ${path} — restrict access and enforce strong DB creds`
            });
            break;
        }
    }
}
