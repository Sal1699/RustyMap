// @name: snmptrap-service
// @description: SNMP trap port open
// @category: misc
// @severity: low
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 162 { continue; }
    findings.push(#{ severity: "low", port: 162, message: "SNMP trap port open" });
}
