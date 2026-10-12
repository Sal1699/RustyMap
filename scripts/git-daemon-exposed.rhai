// @name: git-daemon-exposed
// @description: git:// daemon open (anon repo access)
// @category: misc
// @severity: medium
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 9418 { continue; }
    findings.push(#{ severity: "medium", port: 9418, message: "git:// daemon open (anon repo access)" });
}
