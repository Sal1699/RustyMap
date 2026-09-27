// @name: http-ds-store
// @description: Detect a leaked macOS .DS_Store (reveals filenames)
// @category: http
// @severity: low
// @tags: http, exposure, info-leak
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 { continue; }
    let scheme = if p.port == 443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/.DS_Store`, 3000);
    if resp.status != 200 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    // .DS_Store starts with the "Bud1" magic.
    if body.index_of("Bud1") >= 0 {
        findings.push(#{ severity: "low", port: p.port, message: "leaked /.DS_Store — enumerates directory filenames (map hidden paths)" });
    }
}
