// @name: seaweedfs-exposed
// @description: Detect an exposed SeaweedFS master/volume/filer
// @category: storage
// @severity: medium
// @tags: seaweedfs, storage, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 9333 && p.port != 8888 && p.port != 8080 { continue; }
    let resp = http_get(`http://${host.ip}:${p.port}/cluster/status`, 3000);
    let hdr = if type_of(resp.headers) == "string" { resp.headers.to_lower() } else { "" };
    let body = if type_of(resp.body) == "string" { resp.body.to_lower() } else { "" };
    if hdr.index_of("seaweedfs") >= 0 || body.index_of("seaweedfs") >= 0 || body.index_of("\"leader\"") >= 0 {
        findings.push(#{ severity: "medium", port: p.port, message: "SeaweedFS endpoint reachable — verify the filer/volume servers aren't publicly writable" });
    }
}
