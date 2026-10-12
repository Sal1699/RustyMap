// @name: activemq-openwire
// @description: ActiveMQ OpenWire open
// @category: misc
// @severity: medium
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 61616 { continue; }
    findings.push(#{ severity: "medium", port: 61616, message: "ActiveMQ OpenWire open" });
}
