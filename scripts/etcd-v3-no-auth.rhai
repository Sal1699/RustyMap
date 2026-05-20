// Active probe: etcd v3 client API. The /version endpoint is always
// public, but if /v3/auth/status reports "enabled":false the cluster
// accepts data-plane operations from anyone.
// @name: etcd-v3-no-auth
// @description: Detect etcd v3 clusters with auth disabled
// @category: vuln
// @severity: critical
// @tags: etcd kubernetes secrets
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 2379 && p.port != 2380 { continue; }
    let scheme = if p.port == 2380 { "https" } else { "http" };
    let base = `${scheme}://${host.ip}:${p.port}`;
    let v = http_get(`${base}/version`, 2500);
    if v.status != 200 || !regex_match("etcdserver", v.body) { continue; }
    let ver = regex_capture(`"etcdserver":"([^"]+)"`, v.body);
    let st = http_get(`${base}/v3/auth/status`, 2500);
    if st.status == 200 && regex_match(`"enabled":\\s*false`, st.body) {
        findings.push(#{
            severity: "critical",
            port: p.port,
            message: `etcd ${ver} v3 API has auth disabled — keys+secrets readable by anyone`
        });
    }
}
