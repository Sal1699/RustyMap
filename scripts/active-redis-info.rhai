// Active probe: Redis INFO command. If the server responds without
// auth, it leaks version + role + replication topology + memory.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 6379 && p.port != 6380 { continue; }
    // Redis text protocol: "INFO\r\n"
    let resp = tcp_send(host.ip, p.port, "INFO\r\n", 2000);
    if resp == "" { continue; }
    if resp.contains("NOAUTH") || resp.contains("Authentication required") {
        findings.push(#{
            severity: "info",
            port: p.port,
            message: "Redis requires auth (NOAUTH on INFO)"
        });
        continue;
    }
    if resp.contains("redis_version:") {
        // Extract version
        let i = resp.index_of("redis_version:");
        let line_end = resp.index_of("\r\n", i);
        let line_end_n = if line_end < 0 { resp.len } else { line_end };
        let line = resp.sub_string(i, line_end_n - i);
        findings.push(#{
            severity: "critical",
            port: p.port,
            message: `Redis without auth — INFO leaked: ${line}`
        });
    }
}
