// Active probe: GET / on Elasticsearch. Without xpack security the
// root endpoint returns cluster name + version. With security it
// returns 401.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 9200 && p.port != 9201 { continue; }
    let url = `http://${host.ip}:${p.port}/`;
    let resp = http_get(url, 3000);
    if resp.status == 401 || resp.status == 403 {
        findings.push(#{
            severity: "info",
            port: p.port,
            message: "Elasticsearch with auth (401/403 on /)"
        });
        continue;
    }
    if resp.status == 200 && resp.body.contains("\"cluster_name\"") {
        // Extract version + cluster name
        let cluster = "?";
        let cn_i = resp.body.index_of("\"cluster_name\"");
        if cn_i >= 0 {
            let v_start = resp.body.index_of(":\"", cn_i) + 2;
            let v_end = resp.body.index_of("\"", v_start);
            if v_end > v_start {
                cluster = resp.body.sub_string(v_start, v_end - v_start);
            }
        }
        let version = "?";
        let v_i = resp.body.index_of("\"number\"");
        if v_i >= 0 {
            let s = resp.body.index_of(":\"", v_i) + 2;
            let e = resp.body.index_of("\"", s);
            if e > s {
                version = resp.body.sub_string(s, e - s);
            }
        }
        findings.push(#{
            severity: "critical",
            port: p.port,
            message: `Elasticsearch without auth — cluster='${cluster}' version=${version}`
        });
    }
}
