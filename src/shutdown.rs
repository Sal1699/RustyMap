use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub type Cancel = Arc<AtomicBool>;

pub fn install_handler() -> Cancel {
    let cancel: Cancel = Arc::new(AtomicBool::new(false));
    let c = Arc::clone(&cancel);
    let _ = ctrlc::set_handler(move || {
        if c.load(Ordering::Relaxed) {
            // second Ctrl+C: hard exit
            std::process::exit(130);
        }
        eprintln!("\n[!] Interrupt received. Finishing in-flight probes and saving partial state. Press Ctrl+C again to force exit.");
        c.store(true, Ordering::Relaxed);
    });
    cancel
}
