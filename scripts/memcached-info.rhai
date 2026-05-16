// Active probe: memcached UDP "stats" leak. Memcached on UDP 11211 with
// no auth happily replies to "stats\r\n" with version + uptime + curr_items
// and is also a known UDP amplification vector (CVE-2018-1000115).
// @name memcached-info
// @description Detect memcached servers responding to unauthenticated UDP stats
// @category vuln
// @severity high
// @tags memcached udp amplification ddos
// @cve CVE-2018-1000115
// @references https://nvd.nist.gov/vuln/detail/CVE-2018-1000115
// @author rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 11211 { continue; }
    // Memcached UDP frame: 8-byte header + ASCII command
    //   2B req-id, 2B seq, 2B total dgrams, 2B reserved, then "stats\r\n"
    let req = hex_decode("0001000000010000") + "stats\r\n";
    let resp = udp_send(host.ip, p.port, req, 2000);
    if resp == "" { continue; }
    if regex_match("STAT version ", resp) {
        let ver = regex_capture("STAT version ([^\\r\\n]+)", resp);
        findings.push(#{
            severity: "high",
            port: p.port,
            message: `memcached UDP ${ver} responds to unauth stats — DDoS amplification risk (CVE-2018-1000115)`
        });
    }
}
