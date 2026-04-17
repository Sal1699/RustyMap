fn main() {
    if cfg!(target_os = "windows") {
        let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
        let lib_dir = match arch.as_str() {
            "x86_64" => format!("{}/vendor/npcap-sdk/x64", manifest),
            "x86" => format!("{}/vendor/npcap-sdk/x86", manifest),
            "aarch64" => format!("{}/vendor/npcap-sdk/ARM64", manifest),
            _ => format!("{}/vendor/npcap-sdk/x64", manifest),
        };
        println!("cargo:rustc-link-search=native={}", lib_dir);
    }
}
