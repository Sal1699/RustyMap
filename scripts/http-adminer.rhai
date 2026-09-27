// @name: http-adminer
// @description: Detect an exposed Adminer database front-end
// @category: http
// @severity: medium
// @tags: http, adminer, database, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 { continue; }
    let scheme = if p.port == 443 { "https" } else { "http" };
    for path in ["/adminer.php", "/adminer/", "/adminer"] {
        let resp = http_get(`${scheme}://${host.ip}:${p.port}${path}`, 3000);
        if resp.status != 200 { continue; }
        let body = if type_of(resp.body) == "string" { resp.body } else { "" };
        if body.index_of("Adminer") >= 0 && body.index_of("login") >= 0 {
            findings.push(#{ severity: "medium", port: p.port, message: `Adminer exposed at ${path} — one-form access to any reachable DB` });
            break;
        }
    }
}
