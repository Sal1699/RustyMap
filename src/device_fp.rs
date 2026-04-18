use crate::scanner::{HostResult, PortState};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceClass {
    Router,
    Switch,
    AccessPoint,
    Firewall,
    IpCamera,
    Printer,
    Nas,
    Voip,
    IotHub,
    SmartTv,
    MediaServer,
    GameConsole,
    MobileDevice,
    DesktopPc,
    Server,
    Hypervisor,
    IndustrialControl,
    Unknown,
}

impl DeviceClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceClass::Router => "router",
            DeviceClass::Switch => "switch",
            DeviceClass::AccessPoint => "access point",
            DeviceClass::Firewall => "firewall",
            DeviceClass::IpCamera => "IP camera",
            DeviceClass::Printer => "printer",
            DeviceClass::Nas => "NAS / file server",
            DeviceClass::Voip => "VoIP phone",
            DeviceClass::IotHub => "IoT hub",
            DeviceClass::SmartTv => "smart TV",
            DeviceClass::MediaServer => "media server",
            DeviceClass::GameConsole => "game console",
            DeviceClass::MobileDevice => "mobile device",
            DeviceClass::DesktopPc => "desktop / laptop",
            DeviceClass::Server => "server",
            DeviceClass::Hypervisor => "hypervisor",
            DeviceClass::IndustrialControl => "ICS/SCADA",
            DeviceClass::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceGuess {
    pub class: DeviceClass,
    pub confidence: u8,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub model: Option<String>,
    pub hints: Vec<String>,
}

impl DeviceGuess {
    fn bump(&mut self, class: DeviceClass, confidence: u8, hint: &str) {
        if confidence > self.confidence {
            self.class = class;
            self.confidence = confidence;
        }
        self.hints.push(hint.to_string());
    }
}

// Compact OUI vendor table. 3-byte MAC prefix → vendor name.
// Focused on pentest-relevant devices: network gear, IoT, cameras, printers, common endpoints.
// Sorted by prefix for binary search.
const OUI_TABLE: &[([u8; 3], &str)] = &[
    ([0x00, 0x00, 0x0C], "Cisco"),
    ([0x00, 0x00, 0x48], "Epson"),
    ([0x00, 0x00, 0x85], "Canon"),
    ([0x00, 0x00, 0xF0], "Samsung"),
    ([0x00, 0x01, 0xE6], "HP"),
    ([0x00, 0x03, 0x93], "Apple"),
    ([0x00, 0x03, 0xFF], "Microsoft"),
    ([0x00, 0x05, 0x02], "Apple"),
    ([0x00, 0x05, 0x5D], "D-Link"),
    ([0x00, 0x05, 0x69], "VMware"),
    ([0x00, 0x07, 0xAB], "Samsung"),
    ([0x00, 0x08, 0x9B], "QNAP"),
    ([0x00, 0x0A, 0x95], "Apple"),
    ([0x00, 0x0C, 0x29], "VMware"),
    ([0x00, 0x0C, 0x42], "MikroTik"),
    ([0x00, 0x0D, 0x3A], "Microsoft"),
    ([0x00, 0x0E, 0x7F], "HP"),
    ([0x00, 0x11, 0x32], "Synology"),
    ([0x00, 0x12, 0xFB], "Samsung"),
    ([0x00, 0x13, 0x46], "D-Link"),
    ([0x00, 0x14, 0x6C], "Netgear"),
    ([0x00, 0x14, 0x56], "Brother"),
    ([0x00, 0x1A, 0x4B], "HP"),
    ([0x00, 0x1B, 0xD4], "Cisco"),
    ([0x00, 0x1C, 0xF6], "Cisco"),
    ([0x00, 0x1E, 0x8F], "Canon"),
    ([0x00, 0x23, 0x54], "Asus"),
    ([0x00, 0x26, 0xAB], "Epson"),
    ([0x00, 0x40, 0x8C], "Axis Communications"),
    ([0x00, 0x50, 0x56], "VMware"),
    ([0x00, 0x80, 0x77], "Brother"),
    ([0x04, 0x18, 0xD6], "Ubiquiti"),
    ([0x04, 0xD9, 0xF5], "Asus"),
    ([0x08, 0x00, 0x27], "VirtualBox"),
    ([0x08, 0x00, 0x37], "Canon"),
    ([0x08, 0xA1, 0x89], "Dahua"),
    ([0x14, 0xDD, 0xA9], "Asus"),
    ([0x24, 0xA4, 0x3C], "Ubiquiti"),
    ([0x28, 0xBA, 0xB5], "Samsung"),
    ([0x30, 0x05, 0x5C], "Brother"),
    ([0x34, 0x08, 0x04], "D-Link"),
    ([0x3C, 0xEF, 0x8C], "Dahua"),
    ([0x44, 0x19, 0xB6], "Hikvision"),
    ([0x48, 0x8F, 0x5A], "MikroTik"),
    ([0x4C, 0x11, 0xBF], "Dahua"),
    ([0x50, 0xC7, 0xBF], "TP-Link"),
    ([0x52, 0x54, 0x00], "QEMU/KVM"),
    ([0x60, 0x38, 0xE0], "TP-Link"),
    ([0x68, 0x72, 0x51], "Ubiquiti"),
    ([0x6C, 0x3B, 0x6B], "MikroTik"),
    ([0x7C, 0x1E, 0x52], "Microsoft"),
    ([0xA0, 0x40, 0xA0], "Netgear"),
    ([0xA0, 0xF3, 0xC1], "TP-Link"),
    ([0xAC, 0xCC, 0x8E], "Axis Communications"),
    ([0xB8, 0x27, 0xEB], "Raspberry Pi"),
    ([0xB8, 0x69, 0xF4], "MikroTik"),
    ([0xB8, 0xA4, 0x4F], "Axis Communications"),
    ([0xBC, 0xAD, 0x28], "Hikvision"),
    ([0xC0, 0x3F, 0x0E], "Netgear"),
    ([0xC0, 0x56, 0xE3], "Hikvision"),
    ([0xDC, 0x9F, 0xDB], "Ubiquiti"),
    ([0xDC, 0xA6, 0x32], "Raspberry Pi"),
    ([0xE4, 0x5F, 0x01], "Raspberry Pi"),
];

pub fn vendor_from_mac(mac: &[u8; 6]) -> Option<&'static str> {
    let prefix = [mac[0], mac[1], mac[2]];
    OUI_TABLE
        .binary_search_by(|(p, _)| p.cmp(&prefix))
        .ok()
        .map(|idx| OUI_TABLE[idx].1)
}

fn banners(host: &HostResult) -> String {
    let mut buf = String::new();
    for p in &host.ports {
        if let Some(svc) = &p.service {
            if let Some(b) = &svc.banner {
                buf.push_str(b);
                buf.push(' ');
            }
            buf.push_str(&svc.display());
            buf.push(' ');
        }
    }
    buf.to_lowercase()
}

fn open_ports(host: &HostResult) -> Vec<u16> {
    host.ports
        .iter()
        .filter(|p| p.state == PortState::Open)
        .map(|p| p.port)
        .collect()
}

pub fn classify(host: &HostResult, mac: Option<&[u8; 6]>) -> DeviceGuess {
    let mut g = DeviceGuess {
        class: DeviceClass::Unknown,
        confidence: 0,
        vendor: mac.and_then(vendor_from_mac).map(|s| s.to_string()),
        model: None,
        hints: Vec::new(),
    };

    if let Some(v) = &g.vendor {
        g.hints.push(format!("vendor (MAC OUI): {}", v));
    }

    let ports = open_ports(host);
    let has = |p: u16| ports.contains(&p);
    let banner = banners(host);
    let contains = |needle: &str| banner.contains(needle);

    // ── Virtualization / Hypervisors (MAC-based, strong signal) ──
    if matches!(
        g.vendor.as_deref(),
        Some("VMware") | Some("VirtualBox") | Some("QEMU/KVM")
    ) {
        g.bump(DeviceClass::Hypervisor, 70, "virtual NIC vendor OUI");
    }

    // ── IP cameras ──
    if has(554) || has(8554) {
        g.bump(DeviceClass::IpCamera, 70, "RTSP port 554/8554 open");
    }
    if contains("hikvision") {
        g.bump(DeviceClass::IpCamera, 95, "Hikvision banner");
        g.vendor = Some("Hikvision".into());
    }
    if contains("dahua") {
        g.bump(DeviceClass::IpCamera, 95, "Dahua banner");
        g.vendor = Some("Dahua".into());
    }
    if contains("axis") && (has(80) || has(443) || has(554)) {
        g.bump(DeviceClass::IpCamera, 90, "Axis banner + HTTP/RTSP");
        g.vendor = Some("Axis Communications".into());
    }
    if matches!(g.vendor.as_deref(), Some("Axis Communications") | Some("Hikvision") | Some("Dahua")) {
        g.bump(DeviceClass::IpCamera, 90, "camera vendor OUI");
    }

    // ── Printers ──
    if has(9100) || has(631) || has(515) {
        g.bump(DeviceClass::Printer, 75, "JetDirect/IPP/LPD port open");
    }
    if contains("laserjet") || contains("deskjet") || contains("officejet") {
        g.bump(DeviceClass::Printer, 95, "HP LaserJet/DeskJet banner");
        g.vendor.get_or_insert_with(|| "HP".into());
    }
    if contains("canon") && (has(631) || has(9100) || has(80)) {
        g.bump(DeviceClass::Printer, 90, "Canon printer banner");
        g.vendor.get_or_insert_with(|| "Canon".into());
    }
    if contains("brother") && (has(631) || has(9100) || has(80)) {
        g.bump(DeviceClass::Printer, 90, "Brother printer banner");
        g.vendor.get_or_insert_with(|| "Brother".into());
    }
    if contains("epson") && (has(631) || has(9100) || has(80)) {
        g.bump(DeviceClass::Printer, 90, "Epson printer banner");
        g.vendor.get_or_insert_with(|| "Epson".into());
    }

    // ── NAS ──
    if has(5000) && has(5001) {
        g.bump(DeviceClass::Nas, 85, "Synology DSM ports");
        g.vendor.get_or_insert_with(|| "Synology".into());
    }
    if contains("synology") {
        g.bump(DeviceClass::Nas, 95, "Synology banner");
        g.vendor.get_or_insert_with(|| "Synology".into());
    }
    if contains("qnap") {
        g.bump(DeviceClass::Nas, 95, "QNAP banner");
        g.vendor.get_or_insert_with(|| "QNAP".into());
    }
    if matches!(g.vendor.as_deref(), Some("Synology") | Some("QNAP")) {
        g.bump(DeviceClass::Nas, 90, "NAS vendor OUI");
    }
    if has(2049) || (has(445) && has(548) && has(631)) {
        g.bump(DeviceClass::Nas, 65, "NFS or multi-protocol file sharing");
    }

    // ── Routers / switches / APs / firewalls ──
    if contains("mikrotik") || contains("routeros") {
        g.bump(DeviceClass::Router, 95, "MikroTik/RouterOS banner");
        g.vendor.get_or_insert_with(|| "MikroTik".into());
    }
    if contains("cisco ios") || contains("cisco-ios") {
        g.bump(DeviceClass::Router, 95, "Cisco IOS banner");
        g.vendor.get_or_insert_with(|| "Cisco".into());
    }
    if contains("pfsense") || contains("opnsense") {
        g.bump(DeviceClass::Firewall, 95, "pfSense/OPNsense banner");
    }
    if contains("dd-wrt") || contains("openwrt") {
        g.bump(DeviceClass::Router, 90, "DD-WRT/OpenWrt banner");
    }
    if contains("tp-link") && (has(80) || has(443)) {
        g.bump(DeviceClass::Router, 85, "TP-Link web banner");
        g.vendor.get_or_insert_with(|| "TP-Link".into());
    }
    if contains("ubiquiti") || contains("unifi") || contains("edgeos") {
        g.bump(DeviceClass::Router, 90, "Ubiquiti/UniFi banner");
        g.vendor.get_or_insert_with(|| "Ubiquiti".into());
    }
    if matches!(g.vendor.as_deref(), Some("Cisco") | Some("MikroTik") | Some("Ubiquiti") | Some("TP-Link") | Some("Netgear") | Some("D-Link"))
        && g.class != DeviceClass::IpCamera
        && g.class != DeviceClass::Printer
        && (has(23) || has(80) || has(443) || has(8080) || has(8443))
    {
        g.bump(DeviceClass::Router, 75, "networking vendor OUI + admin iface");
    }

    // ── VoIP ──
    if has(5060) || has(5061) {
        g.bump(DeviceClass::Voip, 75, "SIP port open");
    }
    if contains("asterisk") || contains("freepbx") {
        g.bump(DeviceClass::Voip, 90, "Asterisk/FreePBX banner");
    }

    // ── Smart TV / media ──
    if contains("samsung tv") || contains("smart tv") || contains("webos") {
        g.bump(DeviceClass::SmartTv, 85, "Smart TV banner");
    }
    if contains("plex") || contains("jellyfin") || contains("emby") {
        g.bump(DeviceClass::MediaServer, 85, "media server banner");
    }

    // ── Game console ──
    if matches!(g.vendor.as_deref(), Some("Microsoft")) && (has(3074) || has(3075)) {
        g.bump(DeviceClass::GameConsole, 80, "Xbox Live port + Microsoft OUI");
    }

    // ── Industrial control (ICS/SCADA) ──
    if has(102) || has(502) || has(20000) || has(44818) {
        g.bump(DeviceClass::IndustrialControl, 80, "ICS protocol port open (S7/Modbus/DNP3/EtherNet-IP)");
    }

    // ── Server vs desktop ──
    if has(22) && (has(80) || has(443)) && !has(3389) && !has(445) {
        g.bump(DeviceClass::Server, 55, "SSH + HTTP, no SMB/RDP");
    }
    if has(3389) && has(445) {
        g.bump(DeviceClass::DesktopPc, 55, "RDP + SMB (Windows endpoint)");
    }
    if has(22) && has(5900) {
        g.bump(DeviceClass::DesktopPc, 60, "SSH + VNC (Linux desktop)");
    }
    if has(80) && has(8080) && has(25) && has(110) {
        g.bump(DeviceClass::Server, 70, "web + mail ports (multi-service server)");
    }

    // ── Raspberry Pi / small Linux ──
    if matches!(g.vendor.as_deref(), Some("Raspberry Pi")) {
        if has(22) {
            g.bump(DeviceClass::Server, 75, "Raspberry Pi with SSH");
        }
        g.hints.push("likely single-board computer".into());
    }

    // ── OS hint fallback ──
    if g.class == DeviceClass::Unknown {
        if let Some(os) = &host.os {
            if os.family.contains("Cisco") || os.family.contains("router") {
                g.bump(DeviceClass::Router, 50, "OS fingerprint suggests network device");
            } else if os.family.starts_with("Windows") {
                g.bump(DeviceClass::DesktopPc, 40, "Windows OS fingerprint");
            } else if os.family.starts_with("Linux") {
                g.bump(DeviceClass::Server, 40, "Linux OS fingerprint");
            }
        }
    }

    g
}
