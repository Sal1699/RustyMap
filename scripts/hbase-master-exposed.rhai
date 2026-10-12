// @name: hbase-master-exposed
// @description: HBase master UI open
// @category: db
// @severity: medium
// @tags: db, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 16010 { continue; }
    findings.push(#{ severity: "medium", port: 16010, message: "HBase master UI open" });
}
