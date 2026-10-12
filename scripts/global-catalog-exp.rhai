// @name: global-catalog-exp
// @description: AD Global Catalog (LDAP) open
// @category: dir
// @severity: low
// @tags: dir, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 3268 { continue; }
    findings.push(#{ severity: "low", port: 3268, message: "AD Global Catalog (LDAP) open" });
}
