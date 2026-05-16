// Active probe: Android Debug Bridge over TCP. Devices that ran
// `adb tcpip 5555` (common on dev kits / TV boxes) accept shell
// commands from anyone on the network with no auth.
// @name android-adb-exposed
// @description Detect Android Debug Bridge (adb) exposed on TCP without authentication
// @category vuln
// @severity critical
// @tags android adb mobile
// @author rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5555 { continue; }
    // ADB sync packet: A_CNXN (0x4e584e43) + version + maxdata + payload
    // 24-byte header + payload "host::\0"
    let pkt = hex_decode("434e584e000000010000100000060000") +
              hex_decode("32020000bcb1a7b1") + "host::" + hex_decode("00");
    let resp = tcp_send(host.ip, p.port, pkt, 2500);
    if resp == "" { continue; }
    // Server responds with A_CNXN reply starting "CNXN" (in big-endian dump)
    // or "AUTH" if it wants the user to authorize. AUTH means key-gated,
    // CNXN means open.
    if resp.contains("device::") || resp.contains("CNXN") {
        findings.push(#{
            severity: "critical",
            port: p.port,
            message: "adb daemon accepts connections without authorization — full device shell"
        });
    }
}
