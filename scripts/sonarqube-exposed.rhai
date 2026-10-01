// @name: sonarqube-exposed
// @description: Detect an exposed SonarQube instance and its version
// @category: devops
// @severity: medium
// @tags: sonarqube, ci, code-quality, exposure
// @author: rustymap
// SonarQube's /api/system/status endpoint answers unauthenticated with the
// server id, version and UP/DOWN state. An internet-facing SonarQube leaks
// source-code quality data and often ships with admin/admin defaults.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 9000 && p.port != 9001 { continue; }
    let resp = http_get(`http://${host.ip}:${p.port}/api/system/status`, 3000);
    if resp.status != 200 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if body.index_of("\"status\"") < 0 { continue; }
    let ver = regex_capture("\"version\"\\s*:\\s*\"([^\"]+)\"", body);
    findings.push(#{
        severity: "medium",
        port: p.port,
        message: `SonarQube exposed (version ${ver}) — check for default admin credentials`
    });
}
