// @name: modbus-exposed
// @description: Modbus/TCP open (ICS PLC — must be isolated)
// @category: ics
// @severity: high
// @tags: ics, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 502 { continue; }
    findings.push(#{ severity: "high", port: 502, message: "Modbus/TCP open (ICS PLC — must be isolated)" });
}
