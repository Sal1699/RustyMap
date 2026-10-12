// @name: kerberos-exposed
// @description: Kerberos KDC open (AS-REP/kerberoast surface)
// @category: dir
// @severity: low
// @tags: dir, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 88 { continue; }
    findings.push(#{ severity: "low", port: 88, message: "Kerberos KDC open (AS-REP/kerberoast surface)" });
}
