// @name: minio-console-exposed
// @description: Detect an exposed MinIO console / S3 API
// @category: storage
// @severity: medium
// @tags: s3, minio, storage, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 9000 && p.port != 9001 { continue; }
    let resp = http_get(`http://${host.ip}:${p.port}/minio/health/live`, 3000);
    let hdr = if type_of(resp.headers) == "string" { resp.headers.to_lower() } else { "" };
    if resp.status == 200 || hdr.index_of("minio") >= 0 {
        findings.push(#{
            severity: "medium",
            port: p.port,
            message: "MinIO endpoint reachable — verify buckets aren't public and default minioadmin creds are changed"
        });
    }
}
