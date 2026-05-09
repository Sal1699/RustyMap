//! PDF report writer using printpdf (pure Rust, no system deps).
//!
//! Layout — A4 portrait, single-column, monospaced body:
//!
//!   1. **Title** ("RustyMap scan report") + scan metadata block
//!      (timestamp, scan type, hosts up / total, elapsed).
//!   2. **Executive summary** rendered as wrapped text (the same
//!      `ExecutiveSummary` produced by `exec_summary::build`).
//!   3. **Per-host detail** — one section per host that responded:
//!      open ports, services, OS guess.
//!
//! Pagination is naïve: we track Y position and start a new page
//! whenever the next line would cross the bottom margin. printpdf's
//! built-in Helvetica is good enough for body text — no font file
//! to ship.

use crate::exec_summary;
use crate::scanner::{HostResult, PortState};
use anyhow::{Context, Result};
use printpdf::{BuiltinFont, Mm, PdfDocument, PdfDocumentReference, PdfLayerReference, PdfPageIndex};
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

const PAGE_W: f32 = 210.0;
const PAGE_H: f32 = 297.0;
const MARGIN_X: f32 = 15.0;
const MARGIN_TOP: f32 = 20.0;
const MARGIN_BOTTOM: f32 = 15.0;
const LINE_H: f32 = 5.0;
const FONT_SIZE: f32 = 10.0;
const TITLE_SIZE: f32 = 16.0;
const HEADING_SIZE: f32 = 12.0;
const MAX_LINE_CHARS: usize = 95; // approximate wrap width at 10pt monospace

struct Pen<'a> {
    doc: &'a PdfDocumentReference,
    page: PdfPageIndex,
    layer: PdfLayerReference,
    font: printpdf::IndirectFontRef,
    bold_font: printpdf::IndirectFontRef,
    y: f32,
}

impl<'a> Pen<'a> {
    fn new(doc: &'a PdfDocumentReference, page: PdfPageIndex, layer: PdfLayerReference) -> Result<Self> {
        let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
        let bold_font = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
        Ok(Self {
            doc,
            page,
            layer,
            font,
            bold_font,
            y: PAGE_H - MARGIN_TOP,
        })
    }

    fn maybe_new_page(&mut self) -> Result<()> {
        if self.y - LINE_H < MARGIN_BOTTOM {
            let (page, layer) = self
                .doc
                .add_page(Mm(PAGE_W), Mm(PAGE_H), "Layer 1");
            self.page = page;
            self.layer = self.doc.get_page(self.page).get_layer(layer);
            self.y = PAGE_H - MARGIN_TOP;
        }
        Ok(())
    }

    fn line(&mut self, text: &str) -> Result<()> {
        for chunk in wrap(text, MAX_LINE_CHARS) {
            self.maybe_new_page()?;
            self.layer.use_text(chunk, FONT_SIZE, Mm(MARGIN_X), Mm(self.y), &self.font);
            self.y -= LINE_H;
        }
        Ok(())
    }

    fn blank(&mut self) {
        self.y -= LINE_H * 0.5;
    }

    fn heading(&mut self, text: &str) -> Result<()> {
        self.maybe_new_page()?;
        self.y -= LINE_H * 0.5;
        self.layer.use_text(text, HEADING_SIZE, Mm(MARGIN_X), Mm(self.y), &self.bold_font);
        self.y -= LINE_H * 1.5;
        Ok(())
    }

    fn title(&mut self, text: &str) -> Result<()> {
        self.layer.use_text(text, TITLE_SIZE, Mm(MARGIN_X), Mm(self.y), &self.bold_font);
        self.y -= LINE_H * 2.0;
        Ok(())
    }
}

fn wrap(input: &str, width: usize) -> Vec<String> {
    if input.len() <= width {
        return vec![input.to_string()];
    }
    let mut out = Vec::new();
    let mut current = String::new();
    for word in input.split_whitespace() {
        if current.len() + word.len() + 1 > width && !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

pub fn write_pdf(
    path: &Path,
    hosts: &[HostResult],
    scan_type: &str,
    started_at: chrono::DateTime<chrono::Local>,
    elapsed_secs: f64,
) -> Result<()> {
    let (doc, page1, layer1) = PdfDocument::new("RustyMap scan report", Mm(PAGE_W), Mm(PAGE_H), "Layer 1");
    let layer = doc.get_page(page1).get_layer(layer1);
    let mut pen = Pen::new(&doc, page1, layer)?;

    pen.title("RustyMap scan report")?;
    pen.line(&format!("Generated: {}", started_at.format("%Y-%m-%d %H:%M:%S %z")))?;
    pen.line(&format!("Scan type: {}", scan_type))?;
    pen.line(&format!("Elapsed: {:.2}s", elapsed_secs))?;
    pen.blank();

    let summary = exec_summary::build(hosts, elapsed_secs);
    pen.heading("Executive summary")?;
    for line in exec_summary::render_text(&summary).lines().skip(1) {
        // skip the first "EXECUTIVE SUMMARY" header — we already drew it
        pen.line(line)?;
    }
    pen.blank();

    pen.heading("Hosts")?;
    for h in hosts.iter().filter(|h| h.up) {
        let header = match &h.target.hostname {
            Some(name) => format!("{} ({})", name, h.target.ip),
            None => h.target.ip.to_string(),
        };
        pen.line(&format!("• {}", header))?;
        if let Some(os) = &h.os {
            pen.line(&format!("    OS: {} (conf {})", os.family, os.confidence))?;
        }
        let open: Vec<&_> = h.ports.iter().filter(|p| p.state == PortState::Open).collect();
        if open.is_empty() {
            pen.line("    no open ports")?;
        } else {
            for p in open {
                let svc = p
                    .service
                    .as_ref()
                    .and_then(|s| s.product.clone())
                    .map(|p| format!(" — {}", p))
                    .unwrap_or_default();
                pen.line(&format!("    {}/tcp open{}", p.port, svc))?;
            }
        }
        pen.blank();
    }

    let f = File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut bw = BufWriter::new(f);
    doc.save(&mut bw).context("save PDF")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_keeps_short_lines_intact() {
        let v = wrap("hello world", 80);
        assert_eq!(v, vec!["hello world"]);
    }

    #[test]
    fn wrap_breaks_long_lines_on_word_boundary() {
        let v = wrap("aaa bbb ccc ddd eee", 7);
        assert!(v.len() > 1);
        for line in &v {
            assert!(line.len() <= 7 || !line.contains(' '));
        }
    }

    #[test]
    fn wrap_handles_single_long_token() {
        let v = wrap("supercalifragilistic", 5);
        assert_eq!(v, vec!["supercalifragilistic"]);
    }
}
