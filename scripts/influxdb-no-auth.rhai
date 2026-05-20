// Active probe: InfluxDB v1 HTTP API. SHOW DATABASES without auth on a
// freshly installed InfluxDB returns the cluster's database list — a
// classic admin-credentialless misconfiguration.
// @name: influxdb-no-auth
// @description: Detect InfluxDB v1 instances with anonymous query access
// @category: vuln
// @severity: high
// @tags: influxdb timeseries database
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8086 { continue; }
    let url = `http://${host.ip}:${p.port}/query?q=SHOW+DATABASES`;
    let resp = http_get(url, 3000);
    if resp.status != 200 { continue; }
    if regex_match(`"name":\\s*"databases"`, resp.body) {
        let dbs = regex_capture(`"values":\\s*\\[([^\\]]+)\\]`, resp.body);
        findings.push(#{
            severity: "high",
            port: p.port,
            message: `InfluxDB v1 SHOW DATABASES without auth: ${dbs}`
        });
    }
}
