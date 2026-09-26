// @name: ssdp-upnp-info
// @description: SSDP M-SEARCH to UPnP (1900/udp) and report the SERVER string
// @category: udp
// @severity: info
// @tags: upnp, ssdp, iot, recon
// @author: rustymap
// NSE-equivalent of upnp-info: an answering SSDP responder names its OS /
// UPnP stack in the SERVER header and leaks a device-description URL.
let msearch = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 1900 { continue; }
    let resp = udp_send(host.ip, p.port, msearch, 2500);
    if resp == "" { continue; }
    let server = regex_capture("(?i)SERVER:\\s*([^\\r\\n]+)", resp);
    let location = regex_capture("(?i)LOCATION:\\s*([^\\r\\n]+)", resp);
    let msg = if server != "" { `UPnP SERVER: ${server.trim()}` } else { "UPnP SSDP responder" };
    findings.push(#{ severity: "info", port: 1900, message: msg });
    if location != "" {
        findings.push(#{ severity: "info", port: 1900, message: `UPnP device description: ${location.trim()}` });
    }
}
