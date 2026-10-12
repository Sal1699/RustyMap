// @name: svn-exposed
// @description: Subversion svnserve open
// @category: misc
// @severity: low
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 3690 { continue; }
    findings.push(#{ severity: "low", port: 3690, message: "Subversion svnserve open" });
}
