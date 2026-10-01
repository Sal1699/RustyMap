// @name: nats-info
// @description: Read the NATS server INFO banner and flag missing auth
// @category: messaging
// @severity: medium
// @tags: nats, messaging, no-auth, fingerprint
// @author: rustymap
// A NATS server greets every client with "INFO {json}\r\n" before any
// command. The JSON carries the version and an "auth_required" flag —
// when false, any client can publish/subscribe to every subject.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 4222 && p.port != 4223 { continue; }
    let banner = tcp_send(host.ip, p.port, "", 2000);
    if banner.index_of("INFO") < 0 || banner.index_of("server_id") < 0 { continue; }
    let ver = regex_capture("\"version\"\\s*:\\s*\"([^\"]+)\"", banner);
    let auth = regex_capture("\"auth_required\"\\s*:\\s*(true|false)", banner);
    if auth == "false" || auth == "" {
        findings.push(#{
            severity: "medium",
            port: p.port,
            message: `NATS ${ver} accepts clients with no authentication (auth_required=false)`
        });
    } else {
        findings.push(#{
            severity: "info",
            port: p.port,
            message: `NATS ${ver} (auth_required=true)`
        });
    }
}
