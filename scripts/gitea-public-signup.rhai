// Active probe: Gitea / Forgejo with open registration. A self-hosted
// git server allowing public signups becomes a free CI compute target
// and code-publish channel.
// @name gitea-public-signup
// @description Detect Gitea/Forgejo instances allowing anyone to register
// @category info
// @severity medium
// @tags gitea forgejo git registration
// @author rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 3000 && p.port != 80 && p.port != 443 { continue; }
    let scheme = if p.port == 443 { "https" } else { "http" };
    let base = `${scheme}://${host.ip}:${p.port}`;
    // Gitea's API root tells us the version and we don't need auth.
    let v = http_get(`${base}/api/v1/version`, 2500);
    if v.status != 200 || !regex_match(`"version":"`, v.body) { continue; }
    let ver = regex_capture(`"version":"([^"]+)"`, v.body);
    // /user/sign_up exists when open registration is allowed.
    let s = http_get(`${base}/user/sign_up`, 2500);
    if s.status == 200 && regex_match("(?i)<form[^>]*action=[\"']/user/sign_up", s.body) {
        findings.push(#{
            severity: "medium",
            port: p.port,
            message: `Gitea/Forgejo ${ver} has open public signup at /user/sign_up`
        });
    }
}
