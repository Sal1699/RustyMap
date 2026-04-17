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
    #[cfg(unix)]
    {
        "Raw-socket scans require root or CAP_NET_RAW. Try: sudo rustymap ..."
    }
    #[cfg(windows)]
    {
        "Raw-socket scans on Windows require Administrator + Npcap. Run as admin, or use --sT for connect scan."
    }
}
