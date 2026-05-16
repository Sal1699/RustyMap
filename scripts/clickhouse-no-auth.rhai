// Active probe: ClickHouse HTTP interface (default port 8123) without
// auth. The /play endpoint and `SELECT 1` query both work anonymously
// when the default user is left unauthenticated.
// @name clickhouse-no-auth
// @description Detect ClickHouse HTTP interface accepting queries without auth
// @category vuln
// @severity high
// @tags clickhouse database http
// @author rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8123 && p.port != 8443 { continue; }
    let scheme = if p.port == 8443 { "https" } else { "http" };
    let url = `${scheme}://${host.ip}:${p.port}/?query=SELECT+version()`;
    let resp = http_get(url, 3000);
    if resp.status != 200 { continue; }
    if regex_match("^\\d+\\.\\d+\\.\\d+", resp.body) {
        let ver = regex_capture("^(\\d+\\.\\d+\\.\\d+)", resp.body);
        findings.push(#{
            severity: "high",
            port: p.port,
            message: `ClickHouse ${ver} accepts SELECT without auth`
        });
    }
}
