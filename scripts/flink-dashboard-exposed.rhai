// Active probe: Apache Flink dashboard. /jars/upload allows arbitrary
// JAR upload + execution; even without that, the dashboard leaks the
// cluster topology and running job graphs.
// @name: flink-dashboard-exposed
// @description: Detect Apache Flink JobManager dashboard without auth (RCE via JAR upload)
// @category: vuln
// @severity: critical
// @tags: flink apache rce dashboard
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8081 { continue; }
    let base = `http://${host.ip}:${p.port}`;
    let conf = http_get(`${base}/config`, 2500);
    if conf.status != 200 { continue; }
    if !regex_match(`"flink-version"`, conf.body) { continue; }
    let ver = regex_capture(`"flink-version":"([^"]+)"`, conf.body);
    // /jars/upload exists on default deploys
    let up = http_get(`${base}/jars`, 2500);
    if up.status == 200 {
        findings.push(#{
            severity: "critical",
            port: p.port,
            message: `Apache Flink ${ver} dashboard exposed — /jars/upload likely permits unauth RCE`
        });
    }
}
