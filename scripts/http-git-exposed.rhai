// @name: http-git-exposed
// @description: Detect a publicly exposed .git directory (source leak)
// @category: http
// @severity: high
// @tags: http, exposure, source-disclosure
// @author: rustymap
// NSE-equivalent of http-git: a reachable /.git/HEAD means the whole
// repository (and its history/secrets) is likely downloadable.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 && p.port != 8443
        && p.port != 8000 && p.port != 8888 { continue; }
    let scheme = if p.port == 443 || p.port == 8443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/.git/HEAD`, 3000);
    if resp.status != 200 { continue; }
    if type_of(resp.body) != "string" { continue; }
    if resp.body.index_of("ref:") == 0 || resp.body.index_of("ref: refs/") >= 0 {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: "exposed .git/HEAD — repository (with history/secrets) is downloadable"
        });
    }
}
