//! Keyboard-driven view of the stored verdicts.

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
use crossterm::{cursor, execute, terminal};
use std::io::{self, Write};

pub fn run(reports: &[crate::model::Report]) -> Result<()> {
    let mut stdout = io::stdout();
    terminal::enable_raw_mode()?;
    execute!(stdout, terminal::EnterAlternateScreen, cursor::Hide)?;
    let mut selected = 0usize;
    let result = (|| -> Result<()> {
        loop {
            execute!(stdout, terminal::Clear(terminal::ClearType::All), cursor::MoveTo(0, 0))?;
            let (_, height) = terminal::size()?;
            writeln!(stdout, "DoubleAgent  ↑/↓ navigate · q quit · {} verdicts", reports.len())?;
            let rows = height.saturating_sub(2) as usize;
            let start = selected.saturating_sub(rows.saturating_sub(1));
            for (idx, report) in reports.iter().enumerate().skip(start).take(rows) {
                let mark = if idx == selected { ">" } else { " " };
                writeln!(
                    stdout,
                    "{mark} {:<8} {:>3}  {}",
                    report.severity,
                    report.scores.final_score,
                    report.path.display()
                )?;
                if idx == selected {
                    for finding in &report.findings {
                        writeln!(stdout, "       {}  {}", finding.rule_id, finding.reason)?;
                    }
                }
            }
            stdout.flush()?;
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Down if selected + 1 < reports.len() => selected += 1,
                    KeyCode::Up if selected > 0 => selected -= 1,
                    _ => {}
                }
            }
        }
        Ok(())
    })();
    let restore = execute!(stdout, cursor::Show, terminal::LeaveAlternateScreen);
    let raw = terminal::disable_raw_mode();
    result?;
    restore?;
    raw?;
    Ok(())
}
