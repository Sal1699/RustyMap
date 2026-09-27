// @name: http-open-dir
// @description: Detect an open directory listing ("Index of /")
// @category: http
// @severity: medium
// @tags: http, exposure, directory-listing
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 && p.port != 8443 { continue; }
    let scheme = if p.port == 443 || p.port == 8443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/`, 3000);
    if resp.status != 200 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if body.index_of("Index of /") >= 0 && body.index_of("Parent Directory") >= 0 {
        findings.push(#{
            severity: "medium",
            port: p.port,
            message: "open directory listing enabled — files are browsable without an index page"
        });
    }
}
