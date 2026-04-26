// Flag IPMI / BMC exposed to the network — full OOB hardware control if
// reachable, and historically full of cipher-zero / weak-default issues.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port == 623 || p.port == 664 {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: "IPMI/RMCP+ on 623 — full BMC OOB control if reachable. Check cipher 0 / default creds (admin/admin, root/calvin)"
        });
    }
    // Common BMC web admin ports
    if p.port == 5900 || p.port == 5901 {
        let svc = p.service;
        let banner = if type_of(svc) == "map" {
            let b = svc.banner;
            if type_of(b) == "string" { b.to_lower() } else { "" }
        } else { "" };
        if banner.contains("ami") || banner.contains("aspeed") || banner.contains("ilo") || banner.contains("idrac") {
            findings.push(#{
                severity: "high",
                port: p.port,
                message: "BMC console (KVM-over-IP) reachable — restrict to mgmt VLAN"
            });
        }
    }
}
