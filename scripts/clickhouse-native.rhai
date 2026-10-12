// @name: clickhouse-native
// @description: ClickHouse native protocol open
// @category: db
// @severity: medium
// @tags: db, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 9000 { continue; }
    findings.push(#{ severity: "medium", port: 9000, message: "ClickHouse native protocol open" });
}
