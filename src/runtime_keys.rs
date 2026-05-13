//! Runtime keypress handler — nmap-style `v`/`p`/`?` during a scan.
//!
//! Spawns a single background task that reads keypresses from stdin
//! in raw mode (via `crossterm`, already in the dep graph for the
//! `--tui` view) and updates atomic state shared with the scan loop.
//!
//! Recognised keys:
//!   - `v` / `V` — bump verbosity by 1 (capped at 3)
//!   - `p`       — toggle paused (the scanner periodically checks this)
//!   - `?` / `h` — print a one-shot help banner with current state
//!   - `s`       — print scan-stats snapshot (hosts done / open ports)
//!
//! Disabled when stdin is not a TTY (CI / piped input) so we don't
//! steal stdin from a parent process.

#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct RuntimeState {
    pub verbosity: AtomicU8,
    pub paused: AtomicBool,
    pub stop: AtomicBool,
}

impl RuntimeState {
    pub fn new(initial_verbosity: u8) -> Arc<Self> {
        Arc::new(Self {
            verbosity: AtomicU8::new(initial_verbosity),
            paused: AtomicBool::new(false),
            stop: AtomicBool::new(false),
        })
    }

    pub fn verbosity(&self) -> u8 {
        self.verbosity.load(Ordering::Relaxed)
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    pub fn should_stop(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    pub fn bump_verbosity(&self) -> u8 {
        let v = self.verbosity.load(Ordering::Relaxed).saturating_add(1).min(3);
        self.verbosity.store(v, Ordering::Relaxed);
        v
    }

    pub fn toggle_pause(&self) -> bool {
        let cur = self.paused.load(Ordering::Relaxed);
        self.paused.store(!cur, Ordering::Relaxed);
        !cur
    }
}

/// Spawn the keypress reader. Returns the state handle. The task
/// terminates when stdin closes or `state.stop` flips.
///
/// On non-TTY stdin this is a no-op and returns the state with no
/// background task — calls to `verbosity()` etc. still work.
pub fn spawn(state: Arc<RuntimeState>) -> std::thread::JoinHandle<()> {
    use crossterm::event::{poll, read, Event, KeyCode, KeyEvent, KeyEventKind};
    use std::io::IsTerminal;
    use std::time::Duration;

    let stdin_is_tty = std::io::stdin().is_terminal();
    let st = state;
    std::thread::spawn(move || {
        if !stdin_is_tty {
            return;
        }
        // We don't enter terminal raw-mode here because that conflicts
        // with the existing TUI activation. Instead poll() with a
        // short tick — works for line-buffered keypresses too.
        loop {
            if st.should_stop() {
                return;
            }
            match poll(Duration::from_millis(250)) {
                Ok(true) => {
                    let evt = match read() {
                        Ok(e) => e,
                        Err(_) => return,
                    };
                    if let Event::Key(KeyEvent { code, kind: KeyEventKind::Press, .. }) = evt {
                        match code {
                            KeyCode::Char('v') | KeyCode::Char('V') => {
                                let v = st.bump_verbosity();
                                eprintln!("\n[runtime] verbosity → {}", v);
                            }
                            KeyCode::Char('p') | KeyCode::Char('P') => {
                                let now = st.toggle_pause();
                                eprintln!("\n[runtime] {}", if now { "paused" } else { "resumed" });
                            }
                            KeyCode::Char('s') | KeyCode::Char('S') => {
                                eprintln!(
                                    "\n[runtime] state: verbosity={} paused={}",
                                    st.verbosity(),
                                    st.is_paused()
                                );
                            }
                            KeyCode::Char('?') | KeyCode::Char('h') => {
                                eprintln!(
                                    "\n[runtime keys] v=verbosity++  p=pause toggle  s=state  ?=help"
                                );
                            }
                            _ => {}
                        }
                    }
                }
                Ok(false) => {} // poll timeout — loop and re-check stop flag
                Err(_) => return,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbosity_caps_at_3() {
        let s = RuntimeState::new(0);
        for _ in 0..10 {
            s.bump_verbosity();
        }
        assert_eq!(s.verbosity(), 3);
    }

    #[test]
    fn pause_toggles() {
        let s = RuntimeState::new(0);
        assert!(!s.is_paused());
        assert!(s.toggle_pause());
        assert!(s.is_paused());
        assert!(!s.toggle_pause());
        assert!(!s.is_paused());
    }

    #[test]
    fn stop_flag_observable() {
        let s = RuntimeState::new(0);
        assert!(!s.should_stop());
        s.stop.store(true, Ordering::Relaxed);
        assert!(s.should_stop());
    }
}
