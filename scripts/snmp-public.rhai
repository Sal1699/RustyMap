// Flag SNMP exposed to the network. Without --sU we can't see the
// community string; we surface presence so the operator follows up.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port == 161 || p.port == 162 {
        findings.push(#{
            severity: "medium",
            port: p.port,
            message: "SNMP reachable — try `snmpwalk -v2c -c public` then `private`. Disable v1/v2c when possible."
        });
    }
    if p.port == 10161 || p.port == 10162 {
        findings.push(#{
            severity: "low",
            port: p.port,
            message: "SNMP-over-TLS port reachable"
        });
    }
}
