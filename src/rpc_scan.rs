//! ONC-RPC portmap enumeration (`-sR` in nmap).
//!
//! Talks to **rpcbind / portmapper** on port 111 (TCP or UDP) and
//! calls the `DUMP` procedure (program 100000 / version 2 /
//! procedure 4) which returns every registered RPC program with its
//! version, transport protocol, and port. That's nmap's `-sR` core
//! signal — useful for enumerating NFS / NIS / mountd / ypserv /
//! status / rstatd / similar daemons.
//!
//! Hand-rolled XDR encoding (everything is 4-byte big-endian
//! aligned, padded). No new crate dependency.
//!
//! Read-only single call.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

const PORTMAP_PROG: u32 = 100000;
const PORTMAP_VERS: u32 = 2;
const PORTMAP_PROC_DUMP: u32 = 4;

const RPC_CALL: u32 = 0;
const RPC_VERSION: u32 = 2;
const AUTH_NONE: u32 = 0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcProgram {
    pub program: u32,
    pub version: u32,
    pub proto: u32,
    pub proto_label: String,
    pub port: u32,
    pub name_hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RpcDump {
    pub host: String,
    pub programs: Vec<RpcProgram>,
}

/// Map a few well-known RPC program numbers to recognisable names.
/// Not exhaustive — but covers everything an attacker typically
/// wants to see at a glance.
const KNOWN_PROGRAMS: &[(u32, &str)] = &[
    (100000, "portmapper"),
    (100003, "nfs"),
    (100005, "mountd"),
    (100021, "nlockmgr"),
    (100024, "status"),
    (100227, "nfs_acl"),
    (100068, "cmsd"),
    (100083, "ttdbserver"),
    (100087, "showmount"),
    (100099, "autofs"),
    (100133, "nsm_addrand"),
    (100143, "sgi_fam"),
    (100221, "rusersd"),
    (300019, "amd"),
    (391002, "sgi_eoe"),
];

fn program_name(num: u32) -> &'static str {
    KNOWN_PROGRAMS
        .iter()
        .find_map(|(n, name)| if *n == num { Some(*name) } else { None })
        .unwrap_or("unknown")
}

fn proto_label(proto: u32) -> &'static str {
    match proto {
        6 => "tcp",
        17 => "udp",
        _ => "?",
    }
}

pub async fn dump_tcp(host: IpAddr, dur: Duration) -> Result<RpcDump> {
    let addr = SocketAddr::new(host, 111);
    let mut s = timeout(dur, TcpStream::connect(addr)).await??;
    let xid = rand_xid();
    let call = build_call(xid, PORTMAP_PROG, PORTMAP_VERS, PORTMAP_PROC_DUMP, &[]);
    // RPC over TCP prefixes each record with a fragment header: 4-byte
    // big-endian length with high bit = last-fragment.
    let mut framed = Vec::with_capacity(4 + call.len());
    let frag_hdr = (call.len() as u32) | 0x8000_0000;
    framed.extend_from_slice(&frag_hdr.to_be_bytes());
    framed.extend_from_slice(&call);
    timeout(dur, s.write_all(&framed)).await??;

    // Read response — first 4 bytes = fragment header
    let mut hdr = [0u8; 4];
    timeout(dur, s.read_exact(&mut hdr)).await??;
    let frag_hdr = u32::from_be_bytes(hdr);
    let len = (frag_hdr & 0x7fff_ffff) as usize;
    if len == 0 || len > 65536 {
        return Err(anyhow!("bogus RPC fragment length {}", len));
    }
    let mut body = vec![0u8; len];
    timeout(dur, s.read_exact(&mut body)).await??;
    let programs = parse_dump_reply(&body, xid)?;
    Ok(RpcDump {
        host: host.to_string(),
        programs,
    })
}

pub async fn dump_udp(host: IpAddr, dur: Duration) -> Result<RpcDump> {
    let bind = if host.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).await?;
    let dst = SocketAddr::new(host, 111);
    let xid = rand_xid();
    let call = build_call(xid, PORTMAP_PROG, PORTMAP_VERS, PORTMAP_PROC_DUMP, &[]);
    timeout(dur, sock.send_to(&call, dst)).await??;
    let mut buf = vec![0u8; 65536];
    let n = timeout(dur, sock.recv(&mut buf)).await??;
    let programs = parse_dump_reply(&buf[..n], xid)?;
    Ok(RpcDump {
        host: host.to_string(),
        programs,
    })
}

fn rand_xid() -> u32 {
    use rand::Rng;
    rand::thread_rng().gen()
}

fn build_call(xid: u32, prog: u32, vers: u32, proc_: u32, args: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(40 + args.len());
    out.extend_from_slice(&xid.to_be_bytes());
    out.extend_from_slice(&RPC_CALL.to_be_bytes());
    out.extend_from_slice(&RPC_VERSION.to_be_bytes());
    out.extend_from_slice(&prog.to_be_bytes());
    out.extend_from_slice(&vers.to_be_bytes());
    out.extend_from_slice(&proc_.to_be_bytes());
    // cred: AUTH_NONE / length 0
    out.extend_from_slice(&AUTH_NONE.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    // verf: AUTH_NONE / length 0
    out.extend_from_slice(&AUTH_NONE.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    // args
    out.extend_from_slice(args);
    out
}

/// Parse a successful DUMP reply: list of (program, version, proto,
/// port) quads terminated by `value-follows = 0`.
fn parse_dump_reply(body: &[u8], expected_xid: u32) -> Result<Vec<RpcProgram>> {
    let mut p = 0usize;
    let xid = read_u32(body, &mut p)?;
    if xid != expected_xid {
        return Err(anyhow!("xid mismatch"));
    }
    let reply_type = read_u32(body, &mut p)?;
    if reply_type != 1 {
        return Err(anyhow!("not a REPLY"));
    }
    let stat = read_u32(body, &mut p)?;
    if stat != 0 {
        return Err(anyhow!("MSG_DENIED"));
    }
    // verf flavor + length
    let _flavor = read_u32(body, &mut p)?;
    let vlen = read_u32(body, &mut p)? as usize;
    p += pad4(vlen);
    let accept_stat = read_u32(body, &mut p)?;
    if accept_stat != 0 {
        return Err(anyhow!("accept_stat={} (not SUCCESS)", accept_stat));
    }

    // Now the DUMP-specific reply: repeated quads of (1, prog, vers, proto, port)
    // terminated by (0).
    let mut programs = Vec::new();
    loop {
        let follows = read_u32(body, &mut p)?;
        if follows == 0 {
            break;
        }
        if programs.len() >= 256 {
            // Cap to avoid runaway parsing on a hostile responder.
            break;
        }
        let prog = read_u32(body, &mut p)?;
        let vers = read_u32(body, &mut p)?;
        let proto = read_u32(body, &mut p)?;
        let port = read_u32(body, &mut p)?;
        programs.push(RpcProgram {
            program: prog,
            version: vers,
            proto,
            proto_label: proto_label(proto).to_string(),
            port,
            name_hint: program_name(prog).to_string(),
        });
    }
    Ok(programs)
}

fn read_u32(buf: &[u8], pos: &mut usize) -> Result<u32> {
    if *pos + 4 > buf.len() {
        return Err(anyhow!("truncated"));
    }
    let v = u32::from_be_bytes([buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]]);
    *pos += 4;
    Ok(v)
}

#[allow(dead_code)]
fn pad4(n: usize) -> usize { (4 - (n % 4)) % 4 }

pub fn print_dump(d: &RpcDump) {
    use colored::*;
    println!();
    println!("{}", format!("RPC portmap dump on {} — {} program(s)", d.host, d.programs.len()).bold());
    if d.programs.is_empty() {
        println!("  {}", "no programs returned (portmapper closed or empty)".dimmed());
        return;
    }
    println!("  {:<12} {:<8} {:<4} {:<6} NAME", "PROGRAM", "VERSION", "PROTO", "PORT");
    for p in &d.programs {
        let line = format!(
            "  {:<12} {:<8} {:<4} {:<6} {}",
            p.program, p.version, p.proto_label, p.port, p.name_hint
        );
        if p.name_hint == "nfs" || p.name_hint == "mountd" {
            println!("{}", line.yellow());
        } else {
            println!("{}", line);
        }
    }
    if d.programs.iter().any(|p| p.name_hint == "nfs") {
        println!("  {}", "NFS exposed — check exports with showmount -e".yellow());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_name_resolves_known_codes() {
        assert_eq!(program_name(100000), "portmapper");
        assert_eq!(program_name(100003), "nfs");
        assert_eq!(program_name(100005), "mountd");
        assert_eq!(program_name(987654), "unknown");
    }

    #[test]
    fn proto_label_maps_iana_codes() {
        assert_eq!(proto_label(6), "tcp");
        assert_eq!(proto_label(17), "udp");
        assert_eq!(proto_label(132), "?");
    }

    #[test]
    fn build_call_has_correct_header_layout() {
        let pkt = build_call(0xDEADBEEF, PORTMAP_PROG, PORTMAP_VERS, PORTMAP_PROC_DUMP, &[]);
        // First 4 bytes = xid
        assert_eq!(&pkt[0..4], &[0xde, 0xad, 0xbe, 0xef]);
        // Next 4 = msg_type CALL (0)
        assert_eq!(&pkt[4..8], &[0, 0, 0, 0]);
        // Next 4 = RPC version (2)
        assert_eq!(&pkt[8..12], &[0, 0, 0, 2]);
        // Next 4 = program (100000 = 0x000186A0)
        assert_eq!(&pkt[12..16], &[0, 1, 0x86, 0xa0]);
        // Next 4 = version (2)
        assert_eq!(&pkt[16..20], &[0, 0, 0, 2]);
        // Next 4 = procedure (4 = DUMP)
        assert_eq!(&pkt[20..24], &[0, 0, 0, 4]);
        // Total: 24 + cred(8) + verf(8) = 40 bytes for empty args
        assert_eq!(pkt.len(), 40);
    }

    #[test]
    fn parse_dump_reply_handles_single_program() {
        // Construct a minimal valid reply: xid, msg_type REPLY(1),
        // reply_stat MSG_ACCEPTED(0), verf flavor+len(8 bytes 0),
        // accept_stat SUCCESS(0), value-follows(1), program quad,
        // value-follows(0).
        let xid: u32 = 0x11223344;
        let mut buf = Vec::new();
        buf.extend_from_slice(&xid.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes()); // REPLY
        buf.extend_from_slice(&0u32.to_be_bytes()); // MSG_ACCEPTED
        buf.extend_from_slice(&0u32.to_be_bytes()); // verf flavor AUTH_NONE
        buf.extend_from_slice(&0u32.to_be_bytes()); // verf length 0
        buf.extend_from_slice(&0u32.to_be_bytes()); // accept SUCCESS
        buf.extend_from_slice(&1u32.to_be_bytes()); // value-follows
        buf.extend_from_slice(&100003u32.to_be_bytes()); // nfs
        buf.extend_from_slice(&3u32.to_be_bytes());      // version 3
        buf.extend_from_slice(&6u32.to_be_bytes());      // tcp
        buf.extend_from_slice(&2049u32.to_be_bytes());   // port 2049
        buf.extend_from_slice(&0u32.to_be_bytes());      // value-follows = end

        let progs = parse_dump_reply(&buf, xid).unwrap();
        assert_eq!(progs.len(), 1);
        assert_eq!(progs[0].program, 100003);
        assert_eq!(progs[0].version, 3);
        assert_eq!(progs[0].proto_label, "tcp");
        assert_eq!(progs[0].port, 2049);
        assert_eq!(progs[0].name_hint, "nfs");
    }

    #[test]
    fn parse_dump_reply_rejects_wrong_xid() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0xAAAAu32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        let r = parse_dump_reply(&buf, 0x1234);
        assert!(r.is_err());
    }
}
