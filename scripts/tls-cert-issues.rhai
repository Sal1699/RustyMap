// Flag TLS certs that are expired, self-signed, or use a weak key.
for p in host.ports {
    if p.state != "open" { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let tls = svc.tls;
    if type_of(tls) != "map" { continue; }

    if tls.expired == true {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: `TLS cert expired (not_after=${tls.not_after})`
        });
    }
    if tls.self_signed == true {
        findings.push(#{
            severity: "low",
            port: p.port,
            message: "TLS cert is self-signed — consider a real CA"
        });
    }
    let bits = tls.key_bits;
    if type_of(bits) == "i64" && bits < 2048 {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: `TLS key ${bits}-bit — below modern minimum (2048 RSA / 256 EC)`
        });
    }
}
