//! Post-scan results browser.
//!
//! Renders a two-pane TUI: a host list on the left and the selected host's
//! ports / service info / TLS / device on the right. Useful when a scan
//! returns hundreds of hosts and the streaming text output scrolls past
//! anything you actually want to read.

use crate::scanner::{HostResult, PortState};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::{execute, terminal};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Terminal;
use std::io::{stdout, Stdout};
use std::time::Duration;

type Term = Terminal<ratatui::backend::CrosstermBackend<Stdout>>;

fn setup() -> Result<Term> {
    terminal::enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, terminal::EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(out);
    Ok(Terminal::new(backend)?)
}

fn restore(term: &mut Term) -> Result<()> {
    terminal::disable_raw_mode()?;
    execute!(term.backend_mut(), terminal::LeaveAlternateScreen)?;
    term.show_cursor()?;
    Ok(())
}

pub fn run(hosts: &[HostResult]) -> Result<()> {
    let mut term = setup()?;
    let res = main_loop(&mut term, hosts);
    restore(&mut term)?;
    res
}

fn main_loop(term: &mut Term, hosts: &[HostResult]) -> Result<()> {
    let mut state = ListState::default();
    if !hosts.is_empty() {
        state.select(Some(0));
    }

    loop {
        term.draw(|f| draw(f, hosts, &mut state))?;

        if event::poll(Duration::from_millis(150))? {
            if let Event::Key(k) = event::read()? {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                match k.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Down | KeyCode::Char('j') => {
                        let i = state.selected().unwrap_or(0);
                        let next = (i + 1).min(hosts.len().saturating_sub(1));
                        state.select(Some(next));
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        let i = state.selected().unwrap_or(0);
                        state.select(Some(i.saturating_sub(1)));
                    }
                    KeyCode::PageDown => {
                        let i = state.selected().unwrap_or(0);
                        let next = (i + 10).min(hosts.len().saturating_sub(1));
                        state.select(Some(next));
                    }
                    KeyCode::PageUp => {
                        let i = state.selected().unwrap_or(0);
                        state.select(Some(i.saturating_sub(10)));
                    }
                    KeyCode::Home => state.select(Some(0)),
                    KeyCode::End => state.select(Some(hosts.len().saturating_sub(1))),
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

fn draw(f: &mut ratatui::Frame, hosts: &[HostResult], state: &mut ListState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(f.area());

    let items: Vec<ListItem> = hosts
        .iter()
        .map(|h| {
            let open = h.ports.iter().filter(|p| p.state == PortState::Open).count();
            let label = format!(
                "{:<22} {:>3} open  {}",
                h.target.ip,
                open,
                h.target.hostname.as_deref().unwrap_or("")
            );
            let style = if h.up {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            ListItem::new(Line::from(Span::styled(label, style)))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" RustyMap — {} hosts (q to quit, ↑↓ navigate) ", hosts.len())),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, chunks[0], state);

    let detail = state
        .selected()
        .and_then(|i| hosts.get(i))
        .map(host_detail)
        .unwrap_or_else(|| vec![Line::from("No host selected")]);

    let para = Paragraph::new(detail)
        .block(Block::default().borders(Borders::ALL).title(" Detail "))
        .wrap(Wrap { trim: false });
    f.render_widget(para, chunks[1]);
}

fn host_detail(h: &HostResult) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let title = if let Some(name) = &h.target.hostname {
        format!("{} ({})", name, h.target.ip)
    } else {
        h.target.ip.to_string()
    };
    lines.push(Line::from(Span::styled(
        title,
        Style::default().add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(format!("Latency: {:.3}s", h.elapsed.as_secs_f64())));
    if let Some(os) = &h.os {
        lines.push(Line::from(format!(
            "OS: {} (confidence {}%)",
            os.family, os.confidence
        )));
    }
    if let Some(d) = &h.device {
        let v = d.vendor.as_deref().unwrap_or("");
        lines.push(Line::from(format!(
            "Device: {} {}({}%)",
            d.class.as_str(),
            if v.is_empty() { "".into() } else { format!("· {} ", v) },
            d.confidence
        )));
    }
    lines.push(Line::from(""));

    let header = Line::from(vec![
        Span::styled("PORT", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("       "),
        Span::styled("STATE", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("      "),
        Span::styled("SERVICE", Style::default().add_modifier(Modifier::BOLD)),
    ]);
    lines.push(header);

    for p in &h.ports {
        let state_str = match p.state {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            PortState::OpenFiltered => "open|filt",
            PortState::Unfiltered => "unfilt",
        };
        let state_color = match p.state {
            PortState::Open => Color::Green,
            PortState::Closed => Color::Red,
            PortState::Filtered => Color::Yellow,
            _ => Color::Cyan,
        };
        let svc = p
            .service
            .as_ref()
            .map(|s| s.display())
            .unwrap_or_default();
        let port_s = format!("{:<10}", format!("{}/tcp", p.port));
        let state_s = format!("{:<10}", state_str);
        lines.push(Line::from(vec![
            Span::raw(port_s),
            Span::styled(state_s, Style::default().fg(state_color)),
            Span::raw(svc),
        ]));
        if let Some(svc) = &p.service {
            if let Some(tls) = &svc.tls {
                let mut summary = String::from("    tls: ");
                summary.push_str(&tls.summary());
                if let Some(b) = tls.key_bits {
                    summary.push_str(&format!(" {}-bit", b));
                }
                lines.push(Line::from(Span::styled(
                    summary,
                    Style::default().fg(Color::Cyan),
                )));
            }
        }
    }
    lines
}
