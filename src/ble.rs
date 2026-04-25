//! Bluetooth Low Energy discovery via btleplug.
//!
//! Cross-platform: bluez D-Bus on Linux, WinRT on Windows, Core Bluetooth on
//! macOS. Discovers nearby BLE advertising devices for a configurable
//! window, then prints name / address / RSSI / advertised services.
//! Useful for finding mobile phones, smart watches, fitness trackers,
//! and IoT gadgets in range that you would otherwise never see on the
//! IP layer.

use anyhow::{anyhow, Result};
use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter};
use btleplug::platform::Manager;
use colored::*;
use std::collections::HashMap;
use std::time::Duration;

fn infer_device_class(name: &str, services: &[String]) -> &'static str {
    let n = name.to_lowercase();
    if n.contains("iphone") || n.contains("ipad") || n.contains("airpods") {
        "Apple device"
    } else if n.contains("galaxy") || n.contains("samsung") {
        "Samsung device"
    } else if n.contains("mi ") || n.contains("xiaomi") || n.contains("redmi") {
        "Xiaomi device"
    } else if n.contains("huawei") || n.contains("honor") {
        "Huawei device"
    } else if n.contains("watch") || n.contains("band") || n.contains("fitbit") {
        "wearable"
    } else if n.contains("tv") {
        "smart TV"
    } else if services.iter().any(|s| s.contains("0000180f")) {
        // Battery Service — usually a wearable or peripheral
        "BLE peripheral"
    } else if services.iter().any(|s| s.contains("00001812")) {
        // HID over GATT — keyboard/mouse/controller
        "BLE HID device"
    } else {
        "BLE device"
    }
}

pub async fn scan(duration_secs: u64) -> Result<()> {
    let manager = Manager::new()
        .await
        .map_err(|e| anyhow!("BLE manager init failed: {}", e))?;
    let adapters = manager
        .adapters()
        .await
        .map_err(|e| anyhow!("BLE adapter enumeration failed: {}", e))?;
    let central = adapters
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!(
            "no BLE adapter found. On Linux: install bluez and enable the service. \
             On Windows: check that Bluetooth is turned on in Settings. \
             On macOS: grant Bluetooth permission in System Settings → Privacy."
        ))?;

    eprintln!(
        "[ble-scan] listening for {}s on the first available adapter...",
        duration_secs
    );
    central
        .start_scan(ScanFilter::default())
        .await
        .map_err(|e| anyhow!("BLE start_scan failed: {}", e))?;

    // Aggregate advertisements. Peripherals typically emit multiple adv
    // packets per second; keep the strongest RSSI seen per address.
    let mut best: HashMap<String, (Option<String>, i16, Vec<String>)> = HashMap::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(duration_secs);
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let peers = central
            .peripherals()
            .await
            .map_err(|e| anyhow!("BLE peripherals() failed: {}", e))?;
        for p in peers {
            let addr = p.address().to_string();
            let props = match p.properties().await {
                Ok(Some(pp)) => pp,
                _ => continue,
            };
            let name = props.local_name.clone();
            let rssi = props.rssi.unwrap_or(i16::MIN);
            let services: Vec<String> =
                props.services.iter().map(|u| u.to_string()).collect();
            let entry = best
                .entry(addr)
                .or_insert_with(|| (name.clone(), rssi, services.clone()));
            if rssi > entry.1 {
                entry.1 = rssi;
            }
            if entry.0.is_none() {
                entry.0 = name;
            }
            if entry.2.is_empty() {
                entry.2 = services;
            }
        }
    }
    let _ = central.stop_scan().await;

    if best.is_empty() {
        println!("\nNo BLE devices discovered.");
        return Ok(());
    }

    // Sort by RSSI (strongest first)
    let mut entries: Vec<_> = best.into_iter().collect();
    entries.sort_by(|a, b| b.1.1.cmp(&a.1.1));

    println!(
        "\n{:<20} {:<6}  {:<20}  {}",
        "BD_ADDR".bold(),
        "RSSI".bold(),
        "CLASS".bold(),
        "NAME (· services)".bold()
    );
    for (addr, (name, rssi, services)) in &entries {
        let name_s = name.as_deref().unwrap_or("<unnamed>");
        let class = infer_device_class(name.as_deref().unwrap_or(""), services);
        let rssi_s = if *rssi == i16::MIN {
            "?".to_string()
        } else {
            format!("{}dBm", rssi)
        };
        let svc_s = if services.is_empty() {
            "".to_string()
        } else {
            let svc_short: Vec<&str> = services
                .iter()
                .take(3)
                .map(|s| {
                    // Shorten to the discriminating UUID fragment (e.g. 0000180f-...)
                    s.get(0..8).unwrap_or(s.as_str())
                })
                .collect();
            format!("  · {}{}", svc_short.join(","), if services.len() > 3 { "…" } else { "" })
        };
        let rssi_colored = if *rssi >= -70 {
            rssi_s.green().to_string()
        } else if *rssi >= -90 {
            rssi_s.yellow().to_string()
        } else {
            rssi_s.normal().to_string()
        };
        println!(
            "{:<20} {:<6}  {:<20}  {}{}",
            addr, rssi_colored, class, name_s, svc_s
        );
    }
    println!("\nFound {} BLE device(s)", entries.len());
    Ok(())
}
