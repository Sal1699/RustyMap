//! Best-effort MAC address spoofing.
//!
//! Linux: shells out to `ip link set <iface> address <mac>` (needs root /
//! CAP_NET_ADMIN). macOS: shells out to `ifconfig <iface> ether <mac>`
//! (needs sudo). Windows: returns a clear error explaining the registry
//! tweak path because there is no portable runtime API.
//!
//! Improvement vs nmap: accept named OUI vendors so the user can type
//! `--spoof-mac vmware` and we generate a random MAC inside that
//! vendor's space. Useful when the goal is "look like another device
//! on this LAN" rather than a specific MAC.

use anyhow::{anyhow, Result};
use rand::Rng;

/// Map a vendor name to an OUI prefix used to randomize the lower 3
/// bytes. `random` returns an arbitrary locally-administered MAC.
fn vendor_oui(name: &str) -> Option<[u8; 3]> {
    match name.to_lowercase().as_str() {
        "vmware" => Some([0x00, 0x50, 0x56]),
        "virtualbox" | "vbox" => Some([0x08, 0x00, 0x27]),
        "qemu" | "kvm" => Some([0x52, 0x54, 0x00]),
        "apple" => Some([0x00, 0x03, 0x93]),
        "samsung" => Some([0x00, 0x07, 0xAB]),
        "cisco" => Some([0x00, 0x00, 0x0C]),
        "huawei" => Some([0x00, 0xE0, 0xFC]),
        "hp" => Some([0x00, 0x01, 0xE6]),
        "intel" => Some([0xB4, 0x96, 0x91]),
        "raspberry" | "rpi" => Some([0xB8, 0x27, 0xEB]),
        _ => None,
    }
}

/// Resolve the spec to a 6-byte MAC. Accepts:
///   - XX:XX:XX:XX:XX:XX (full address)
///   - vendor name (vmware|apple|samsung|cisco|huawei|hp|intel|raspberry|vbox|qemu)
///   - "random" → locally-administered MAC (bit 1 of first byte set)
pub fn resolve(spec: &str) -> Result<[u8; 6]> {
    let s = spec.trim();
    // Full MAC like aa:bb:cc:dd:ee:ff
    if s.len() == 17 && s.chars().nth(2) == Some(':') {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() == 6 {
            let mut out = [0u8; 6];
            for (i, p) in parts.iter().enumerate() {
                out[i] = u8::from_str_radix(p, 16)
                    .map_err(|_| anyhow!("--spoof-mac: invalid byte '{}'", p))?;
            }
            return Ok(out);
        }
    }
    // Random
    if s.eq_ignore_ascii_case("random") {
        let mut rng = rand::thread_rng();
        let mut out: [u8; 6] = rng.gen();
        // Locally administered (bit 1 of first byte) + unicast (bit 0 cleared)
        out[0] = (out[0] & 0xfe) | 0x02;
        return Ok(out);
    }
    // Vendor alias — random lower 3 bytes inside the OUI space
    if let Some(oui) = vendor_oui(s) {
        let mut rng = rand::thread_rng();
        Ok([oui[0], oui[1], oui[2], rng.gen(), rng.gen(), rng.gen()])
    } else {
        Err(anyhow!(
            "--spoof-mac: '{}' is not a MAC or known vendor (try: random, \
             vmware, vbox, qemu, apple, samsung, cisco, huawei, hp, intel, raspberry)",
            s
        ))
    }
}

fn fmt_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Apply the MAC to the named interface. Returns Ok if the OS accepted
/// it. Restoration is the user's responsibility (we don't track the
/// original MAC across runs).
pub fn apply(iface: &str, mac: &[u8; 6]) -> Result<String> {
    let mac_s = fmt_mac(mac);

    #[cfg(target_os = "linux")]
    {
        let status = std::process::Command::new("ip")
            .args(["link", "set", "dev", iface, "address", &mac_s])
            .status();
        match status {
            Ok(s) if s.success() => Ok(mac_s),
            Ok(s) => Err(anyhow!(
                "ip link returned {} — usually means missing CAP_NET_ADMIN, \
                 try: sudo rustymap --spoof-mac ... or sudo setcap \
                 cap_net_admin,cap_net_raw=eip $(which rustymap)",
                s
            )),
            Err(e) => Err(anyhow!("failed to spawn ip(8): {}", e)),
        }
    }

    #[cfg(target_os = "macos")]
    {
        let status = std::process::Command::new("ifconfig")
            .args([iface, "ether", &mac_s])
            .status();
        match status {
            Ok(s) if s.success() => Ok(mac_s),
            Ok(s) => Err(anyhow!(
                "ifconfig returned {} — needs sudo: sudo rustymap --spoof-mac ...",
                s
            )),
            Err(e) => Err(anyhow!("failed to spawn ifconfig: {}", e)),
        }
    }

    #[cfg(windows)]
    {
        let _ = iface;
        let _ = mac_s;
        Err(anyhow!(
            "--spoof-mac is not implemented on Windows: there is no portable \
             runtime API. To set a NIC's MAC manually:\n  \
             1. Open Device Manager → Network Adapters → properties\n  \
             2. Advanced tab → Network Address / MAC Address (driver-specific)\n  \
             3. Or set HKLM\\SYSTEM\\...\\NetworkAdapter\\NetworkAddress in registry\n  \
             4. Disable + re-enable the adapter."
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_mac() {
        let m = resolve("00:11:22:aa:bb:cc").unwrap();
        assert_eq!(m, [0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn vendor_alias_keeps_oui() {
        let m = resolve("vmware").unwrap();
        assert_eq!(&m[..3], &[0x00, 0x50, 0x56]);
    }

    #[test]
    fn random_is_locally_administered() {
        let m = resolve("random").unwrap();
        // bit 1 of first byte set, bit 0 cleared
        assert_eq!(m[0] & 0x03, 0x02);
    }

    #[test]
    fn unknown_errors() {
        assert!(resolve("not-a-vendor").is_err());
    }

    #[test]
    fn fmt_mac_is_lowercase_colon_separated() {
        assert_eq!(fmt_mac(&[0xab, 0xcd, 0xef, 0x01, 0x02, 0x03]), "ab:cd:ef:01:02:03");
    }
}
