pub fn is_privileged() -> bool {
    #[cfg(unix)]
    unsafe {
        libc::geteuid() == 0
    }

    #[cfg(windows)]
    {
        std::process::Command::new("net")
            .arg("session")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

pub fn raw_privilege_hint() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "Raw-socket scans on Linux need CAP_NET_RAW:\n  \
         • quick fix: sudo rustymap ...\n  \
         • durable: sudo setcap cap_net_raw,cap_net_admin=eip $(which rustymap)\n  \
         • if --sS still returns only 'filtered' despite sudo, your iptables \
           may be dropping the SYN-ACK as INVALID. Either allow with:\n    \
             sudo iptables -I INPUT -p tcp --tcp-flags ALL SYN,ACK -j ACCEPT\n  \
           or fall back to --sT (connect scan)."
    }
    #[cfg(target_os = "macos")]
    {
        "Raw-socket scans on macOS need sudo (BPF devices in /dev/bpf* are root-owned).\n  \
         Try: sudo rustymap ...  — or use --sT for connect scan."
    }
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    {
        "Raw-socket scans require root (or equivalent privileges). Try: sudo rustymap ..."
    }
    #[cfg(windows)]
    {
        "Raw-socket scans on Windows require Administrator + Npcap.\n  \
         • Install Npcap: rustymap --install-npcap  (admin)\n  \
         • --sS auto-falls-back to SO_LINGER=0 emulation if Npcap is missing,\n    \
           or force via --syn-emulated."
    }
}
