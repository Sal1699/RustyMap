// @name: zabbix-agent-exposed
// @description: Zabbix agent (10050) open
// @category: misc
// @severity: low
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 10050 { continue; }
    findings.push(#{ severity: "low", port: 10050, message: "Zabbix agent (10050) open" });
}
