// Flag backup services reachable from the network. Restic-server with
// --no-auth, public S3 buckets, rsnapshot exports — all common leaks.
for p in host.ports {
    if p.state != "open" { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let prod = svc.product;
    if type_of(prod) != "string" { continue; }
    let lo = prod.to_lower();
    if lo.contains("restic") {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: "restic-server reachable — verify --no-auth is OFF, .htpasswd is set, and TLS is enforced"
        });
    } else if lo.contains("minio") {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: "MinIO reachable — verify console + S3 API auth, default minioadmin:minioadmin is critical"
        });
    }
}
