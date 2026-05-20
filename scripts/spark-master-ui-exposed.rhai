// Active probe: Apache Spark Master Web UI. The default 8080 UI leaks
// the cluster topology, currently-running applications, and—on older
// versions—lets anyone submit jobs (CVE-2022-33891 unauth RCE).
// @name: spark-master-ui-exposed
// @description: Detect Apache Spark Master UI exposed without auth
// @category: vuln
// @severity: high
// @tags: spark apache cluster ui
// @cve: CVE-2022-33891
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8080 && p.port != 4040 { continue; }
    let url = `http://${host.ip}:${p.port}/`;
    let resp = http_get(url, 3000);
    if resp.status != 200 { continue; }
    if regex_match("(?i)spark master at", resp.body) {
        let ver = regex_capture(`(?i)Spark[^<]*?(\\d+\\.\\d+\\.\\d+)`, resp.body);
        findings.push(#{
            severity: "high",
            port: p.port,
            message: `Spark Master UI ${ver} exposed — leaks topology, check CVE-2022-33891 for RCE`
        });
    }
}
