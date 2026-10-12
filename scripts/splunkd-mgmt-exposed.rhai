// @name: splunkd-mgmt-exposed
// @description: Splunk management API (8089) open
// @category: mgmt
// @severity: low
// @tags: mgmt, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8089 { continue; }
    findings.push(#{ severity: "low", port: 8089, message: "Splunk management API (8089) open" });
}
