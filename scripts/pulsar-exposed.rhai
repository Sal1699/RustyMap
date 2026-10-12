// @name: pulsar-exposed
// @description: Apache Pulsar broker open
// @category: misc
// @severity: low
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 6650 { continue; }
    findings.push(#{ severity: "low", port: 6650, message: "Apache Pulsar broker open" });
}
