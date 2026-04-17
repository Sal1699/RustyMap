// Flag hosts with SMB (445) open to the wider network.
for p in host.ports {
    if p.port == 445 && p.state == "open" {
        findings.push(#{
            severity: "medium",
            port: 445,
            message: "SMB (445/tcp) exposed — verify firewall and authentication"
        });
    }
    if p.port == 3389 && p.state == "open" {
        findings.push(#{
            severity: "high",
            port: 3389,
            message: "RDP (3389/tcp) exposed — ensure NLA and strong auth"
        });
    }
    if p.port == 23 && p.state == "open" {
        findings.push(#{
            severity: "high",
            port: 23,
            message: "Telnet (23/tcp) is cleartext — replace with SSH"
        });
    }
}
