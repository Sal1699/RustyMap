use crate::evasion::{build_ip_packet, build_tcp_segment, EvasionConfig};
use crate::net_util::source_ipv4_for;
use crate::scanner::{HostResult, PortResult, PortState};
use crate::target::Target;
use anyhow::{anyhow, Result};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::Packet;
use pnet::transport::{
    ipv4_packet_iter, transport_channel, TransportChannelType::Layer3, TransportReceiver,
    TransportSender,
};
use rand::Rng;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

type PendingMap = Arc<Mutex<HashMap<(Ipv4Addr, u16), mpsc::Sender<u16>>>>;

pub struct IdleScanner {
    tx: Arc<Mutex<TransportSender>>,
    pending: PendingMap,
    zombie_ip: Ipv4Addr,
    _rx_thread: thread::JoinHandle<()>,
}

impl IdleScanner {
    pub fn new(zombie_ip: Ipv4Addr) -> Result<Self> {
        let (tx, rx) = transport_channel(4096, Layer3(IpNextHeaderProtocols::Tcp))
            .map_err(|e| {
                anyhow!(
                    "failed to open Layer3 IP socket for idle scan: {} — {}",
                    e,
                    crate::privilege::raw_privilege_hint()
                )
            })?;

        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let pending_rx = Arc::clone(&pending);
        let rx_thread = thread::spawn(move || receiver_loop(rx, pending_rx, zombie_ip));

        Ok(Self {
            tx: Arc::new(Mutex::new(tx)),
            pending,
            zombie_ip,
            _rx_thread: rx_thread,
        })
    }

    pub fn zombie(&self) -> Ipv4Addr {
        self.zombie_ip
    }

    /// Send SYN/ACK to zombie's port, expect unsolicited RST back, return its IP ID.
    fn probe_zombie_id(
        &self,
        src_ip: Ipv4Addr,
        zombie_port: u16,
        timeout: Duration,
    ) -> Option<u16> {
        let mut rng = rand::thread_rng();
        let src_port: u16 = rng.gen_range(40000..60000);

        let (sender, receiver) = mpsc::channel::<u16>();
        self.pending
            .lock()
            .unwrap()
            .insert((self.zombie_ip, src_port), sender);

        let cfg = EvasionConfig::default();
        let flags = TcpFlags::SYN | TcpFlags::ACK;
        let tcp = build_tcp_segment(
            src_ip,
            self.zombie_ip,
            zombie_port,
            flags,
            rng.gen(),
            src_port,
            &cfg,
        );
        let ip = build_ip_packet(src_ip, self.zombie_ip, &tcp, cfg.ip_ttl);

        let sent = {
            let mut tx = self.tx.lock().unwrap();
            let pkt = Ipv4Packet::new(&ip).unwrap();
            tx.send_to(pkt, IpAddr::V4(self.zombie_ip)).is_ok()
        };

        let result = if sent {
            receiver.recv_timeout(timeout).ok()
        } else {
            None
        };
        self.pending
            .lock()
            .unwrap()
            .remove(&(self.zombie_ip, src_port));
        result
    }

    /// Send a SYN to target with zombie as spoofed source.
    fn send_spoofed_syn(&self, target_ip: Ipv4Addr, target_port: u16) {
        let mut rng = rand::thread_rng();
        let src_port: u16 = rng.gen_range(40000..60000);
        let cfg = EvasionConfig::default();

        let tcp = build_tcp_segment(
            self.zombie_ip,
            target_ip,
            target_port,
            TcpFlags::SYN,
            rng.gen(),
            src_port,
            &cfg,
        );
        let ip = build_ip_packet(self.zombie_ip, target_ip, &tcp, cfg.ip_ttl);

        let mut tx = self.tx.lock().unwrap();
        let pkt = Ipv4Packet::new(&ip).unwrap();
        let _ = tx.send_to(pkt, IpAddr::V4(target_ip));
    }

    /// Verify zombie has monotonically-incrementing IP IDs (+1 per packet).
    /// Rejects zombies with randomized or 0 IPIDs.
    pub fn qualify(
        &self,
        src_ip: Ipv4Addr,
        zombie_port: u16,
        timeout: Duration,
    ) -> std::result::Result<(), String> {
        let mut ids = Vec::new();
        for _ in 0..4 {
            match self.probe_zombie_id(src_ip, zombie_port, timeout) {
                Some(id) => ids.push(id),
                None => return Err("zombie did not respond to qualification probes".into()),
            }
            thread::sleep(Duration::from_millis(80));
        }
        for pair in ids.windows(2) {
            let d = pair[1].wrapping_sub(pair[0]);
            if d == 0 || d > 3 {
                return Err(format!(
                    "zombie has unsuitable IP IDs {:?} (need near-monotonic +1; got delta {})",
                    ids, d
                ));
            }
        }
        Ok(())
    }

    /// Probe a single target port via the zombie. Returns Open / Closed / Filtered.
    /// Open and Closed are indirect; Filtered covers zombie-unreachable or noisy zombie.
    fn probe_port(
        &self,
        src_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
        port: u16,
        zombie_port: u16,
        timeout: Duration,
    ) -> PortState {
        let id1 = match self.probe_zombie_id(src_ip, zombie_port, timeout) {
            Some(id) => id,
            None => return PortState::Filtered,
        };

        self.send_spoofed_syn(target_ip, port);
        thread::sleep(Duration::from_millis(80));

        let id2 = match self.probe_zombie_id(src_ip, zombie_port, timeout) {
            Some(id) => id,
            None => return PortState::Filtered,
        };

        match id2.wrapping_sub(id1) {
            1 => PortState::Closed,
            2 => PortState::Open,
            _ => PortState::Filtered,
        }
    }
}

fn receiver_loop(mut rx: TransportReceiver, pending: PendingMap, zombie_ip: Ipv4Addr) {
    let mut iter = ipv4_packet_iter(&mut rx);
    while let Ok((ip_packet, addr)) = iter.next() {
        let src = match addr {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => continue,
        };
        if src != zombie_ip {
            continue;
        }
        let ip_id = ip_packet.get_identification();
        if let Some(tcp) = TcpPacket::new(ip_packet.payload()) {
            let our_src_port = tcp.get_destination();
            let sender_opt = {
                let p = pending.lock().unwrap();
                p.get(&(src, our_src_port)).cloned()
            };
            if let Some(s) = sender_opt {
                let _ = s.send(ip_id);
            }
        }
    }
}

pub fn run_idle_scan(
    target: Target,
    ports: Arc<Vec<u16>>,
    scanner: Arc<IdleScanner>,
    zombie_port: u16,
    timeout: Duration,
) -> HostResult {
    let start = Instant::now();
    let dst = match target.ip {
        IpAddr::V4(v) => v,
        IpAddr::V6(_) => {
            return HostResult {
                target,
                up: false,
                ports: vec![],
                elapsed: start.elapsed(),
                os: None,
                device: None,
                mac: None,
            };
        }
    };

    let src = match source_ipv4_for(scanner.zombie()) {
        Ok(s) => s,
        Err(_) => {
            return HostResult {
                target,
                up: false,
                ports: vec![],
                elapsed: start.elapsed(),
                os: None,
                device: None,
                mac: None,
            };
        }
    };

    let mut results = Vec::new();
    for &p in ports.iter() {
        let st = scanner.probe_port(src, dst, p, zombie_port, timeout);
        if matches!(st, PortState::Open) {
            results.push(PortResult {
                port: p,
                state: st,
                rtt: Duration::from_millis(0),
                service: None,
            });
        }
    }

    HostResult {
        up: !results.is_empty(),
        target,
        ports: results,
        elapsed: start.elapsed(),
        os: None,
        device: None,
        mac: None,
    }
}
