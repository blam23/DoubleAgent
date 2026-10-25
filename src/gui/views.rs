//! Window contents: theme, verdict list and detail, and the Options tab.

use super::options::Draft;
use super::{DoubleAgentApp, Tab};
use anyhow::{Context as _, Result};
use doubleagent::config::Config;
use doubleagent::model::{Report, Severity};
use doubleagent::startup;
use doubleagent::store::{QuarantineRow, Store};
use eframe::egui::{self, Align2, Color32, CornerRadius, FontId, Frame, Margin, RichText, Sense, Stroke, StrokeKind, Ui};
use std::path::Path;

const PANEL: Color32 = Color32::from_rgb(20, 23, 29);
const BAR: Color32 = Color32::from_rgb(26, 30, 37);
const CARD: Color32 = Color32::from_rgb(31, 36, 45);
const CARD_HOVER: Color32 = Color32::from_rgb(39, 45, 57);
const SELECTED: Color32 = Color32::from_rgb(33, 58, 56);
const OUTLINE: Color32 = Color32::from_rgb(48, 55, 68);
const ACCENT: Color32 = Color32::from_rgb(74, 173, 136);

pub fn apply_theme(ctx: &egui::Context) {
    ctx.set_theme(egui::ThemePreference::Dark);
    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = egui::vec2(10.0, 8.0);
        style.spacing.button_padding = egui::vec2(14.0, 7.0);
        style.spacing.interact_size.y = 30.0;
        style.spacing.window_margin = Margin::same(16);
        style.spacing.scroll.bar_width = 8.0;
        for (text_style, size) in [
            (egui::TextStyle::Heading, 22.0),
            (egui::TextStyle::Body, 14.5),
            (egui::TextStyle::Button, 14.5),
            (egui::TextStyle::Small, 12.0),
            (egui::TextStyle::Monospace, 13.0),
        ] {
            if let Some(font) = style.text_styles.get_mut(&text_style) {
                font.size = size;
            }
        }
        let visuals = &mut style.visuals;
        visuals.panel_fill = PANEL;
        visuals.window_fill = CARD;
        visuals.extreme_bg_color = Color32::from_rgb(15, 17, 22);
        visuals.selection.bg_fill = ACCENT.gamma_multiply(0.45);
        visuals.hyperlink_color = ACCENT;
        let widgets = &mut visuals.widgets;
        for state in [
            &mut widgets.noninteractive,
            &mut widgets.inactive,
            &mut widgets.hovered,
            &mut widgets.active,
            &mut widgets.open,
        ] {
            state.corner_radius = CornerRadius::same(7);
        }
        widgets.noninteractive.bg_stroke = Stroke::new(1.0, OUTLINE);
        widgets.inactive.weak_bg_fill = Color32::from_rgb(40, 46, 58);
        widgets.inactive.bg_fill = Color32::from_rgb(40, 46, 58);
        widgets.hovered.weak_bg_fill = Color32::from_rgb(52, 60, 75);
        widgets.hovered.bg_fill = Color32::from_rgb(52, 60, 75);
    });
}

fn severity_color(severity: Severity) -> Color32 {
    match severity {
        Severity::Critical => Color32::from_rgb(239, 83, 80),
        Severity::High => Color32::from_rgb(255, 138, 101),
        Severity::Medium => Color32::from_rgb(255, 202, 40),
        Severity::Low => Color32::from_rgb(129, 199, 132),
        Severity::Info => Color32::from_rgb(144, 164, 174),
    }
}

fn pill(ui: &mut Ui, text: &str, color: Color32) {
    Frame::new()
        .fill(color.gamma_multiply(0.2))
        .corner_radius(10)
        .inner_margin(Margin::symmetric(9, 2))
        .show(ui, |ui| {
            ui.label(RichText::new(text).color(color).strong().size(12.0));
        });
}

fn card() -> Frame {
    Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0, OUTLINE))
        .corner_radius(10)
        .inner_margin(Margin::same(16))
}

/// Keep the end of a long path, which is the informative part.
fn shorten(text: &str, max_chars: usize) -> String {
    let count = text.chars().count();
    if count <= max_chars {
        text.to_owned()
    } else {
        let tail: String = text.chars().skip(count - max_chars.saturating_sub(1)).collect();
        format!("…{tail}")
    }
}

/// One row of the verdict list. The whole rectangle is the click target.
fn report_card(ui: &mut Ui, report: &Report, selected: bool) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 76.0), Sense::click());
    let response = response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text(report.path.display().to_string());
    if !ui.is_rect_visible(rect) {
        return response;
    }
    let fill = if selected {
        SELECTED
    } else if response.hovered() {
        CARD_HOVER
    } else {
        CARD
    };
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 9, fill);
    painter.rect_stroke(
        rect,
        9,
        Stroke::new(1.0, if selected { ACCENT } else { OUTLINE }),
        StrokeKind::Inside,
    );
    let color = severity_color(report.severity);
    painter.rect_filled(
        egui::Rect::from_min_max(
            egui::pos2(rect.left() + 6.0, rect.top() + 12.0),
            egui::pos2(rect.left() + 10.0, rect.bottom() - 12.0),
        ),
        2,
        color,
    );

    let text_color = ui.visuals().text_color();
    let weak = ui.visuals().weak_text_color();
    let left = rect.left() + 22.0;
    let name = report.path.file_name().unwrap_or_default().to_string_lossy();
    painter.text(
        egui::pos2(rect.right() - 14.0, rect.top() + 11.0),
        Align2::RIGHT_TOP,
        report.scores.final_score,
        FontId::proportional(16.0),
        color,
    );
    painter
        .with_clip_rect(egui::Rect::from_min_max(rect.min, egui::pos2(rect.right() - 56.0, rect.bottom())))
        .text(
            egui::pos2(left, rect.top() + 11.0),
            Align2::LEFT_TOP,
            name,
            FontId::proportional(15.0),
            text_color,
        );
    let label = painter.text(
        egui::pos2(left, rect.top() + 35.0),
        Align2::LEFT_TOP,
        report.severity.as_str().to_uppercase(),
        FontId::proportional(12.0),
        color,
    );
    let findings = report.findings.len();
    painter.text(
        egui::pos2(label.right() + 8.0, rect.top() + 35.0),
        Align2::LEFT_TOP,
        format!("{findings} finding{}", if findings == 1 { "" } else { "s" }),
        FontId::proportional(12.0),
        weak,
    );
    let dir = report.path.parent().map(|p| p.display().to_string()).unwrap_or_default();
    painter.text(
        egui::pos2(left, rect.top() + 54.0),
        Align2::LEFT_TOP,
        shorten(&dir, ((rect.width() - 36.0) / 6.4) as usize),
        FontId::proportional(11.5),
        weak,
    );
    response
}

fn findings_view(ui: &mut Ui, report: &Report) {
    ui.add_space(8.0);
    ui.label(RichText::new(format!("Findings ({})", report.findings.len())).size(17.0).strong());
    if report.findings.is_empty() {
        hint(ui, "No findings for this file.");
    }
    for finding in &report.findings {
        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(&finding.rule_id).strong().color(ACCENT));
                ui.label(RichText::new(&finding.title).strong());
                for technique in &finding.atlas {
                    pill(ui, &format!("ATLAS {technique}"), Color32::from_rgb(120, 144, 220));
                }
            });
            ui.label(&finding.reason);
            if !finding.excerpt.is_empty() {
                Frame::new()
                    .fill(Color32::from_rgb(15, 17, 22))
                    .corner_radius(7)
                    .inner_margin(Margin::symmetric(12, 8))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(RichText::new(&finding.excerpt).monospace());
                    });
            }
        });
    }
    let notes: Vec<&String> = report.provenance_reasons.iter().chain(report.shadow_reasons.iter()).collect();
    if !notes.is_empty() {
        ui.add_space(8.0);
        ui.label(RichText::new("Provenance & shadowing").size(17.0).strong());
        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            for note in notes {
                ui.label(format!("•  {note}"));
            }
        });
    }
}

fn stat_tile(ui: &mut Ui, label: &str, value: u32, color: Color32) {
    Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0, OUTLINE))
        .corner_radius(10)
        .inner_margin(Margin::symmetric(16, 12))
        .show(ui, |ui| {
            ui.set_min_width(96.0);
            ui.vertical(|ui| {
                ui.label(RichText::new(label).size(12.0).color(ui.visuals().weak_text_color()));
                ui.label(RichText::new(value.to_string()).size(24.0).color(color));
            });
        });
}

fn section(ui: &mut Ui, title: &str, add_contents: impl FnOnce(&mut Ui)) {
    card().show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(RichText::new(title).strong().size(16.0));
        ui.add_space(4.0);
        add_contents(ui);
    });
    ui.add_space(12.0);
}

fn hint(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).size(12.0).color(ui.visuals().weak_text_color()));
}

fn list_editor(ui: &mut Ui, text: &mut String, rows: usize) {
    ui.add(egui::TextEdit::multiline(text).desired_rows(rows).desired_width(f32::INFINITY));
}

fn severity_picker(ui: &mut Ui, id: &str, value: &mut Option<Severity>, allow_off: bool) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(value.map_or("off", |s| s.as_str()))
        .show_ui(ui, |ui| {
            if allow_off {
                ui.selectable_value(value, None, "off");
            }
            for severity in [Severity::Low, Severity::Medium, Severity::High, Severity::Critical] {
                ui.selectable_value(value, Some(severity), severity.as_str());
            }
        });
}

fn open_path(path: &Path) -> Result<()> {
    #[cfg(windows)]
    std::process::Command::new("explorer")
        .arg("/select,")
        .arg(path)
        .spawn()
        .context("starting Explorer")?;
    #[cfg(target_os = "macos")]
    std::process::Command::new("open")
        .arg("-R")
        .arg(path)
        .spawn()
        .context("starting Finder")?;
    #[cfg(target_os = "linux")]
    std::process::Command::new("xdg-open")
        .arg(path.parent().unwrap_or(path))
        .spawn()
        .context("opening file location")?;
    Ok(())
}

fn open_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(windows)]
    std::process::Command::new("explorer")
        .arg(dir)
        .spawn()
        .context("starting Explorer")?;
    #[cfg(target_os = "macos")]
    std::process::Command::new("open").arg(dir).spawn().context("starting Finder")?;
    #[cfg(target_os = "linux")]
    std::process::Command::new("xdg-open").arg(dir).spawn().context("opening folder")?;
    Ok(())
}

enum OptionsAction {
    Save,
    Revert,
    Import,
    Export,
    Reset,
    TestNotification,
}

impl DoubleAgentApp {
    pub fn show(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        self.header(ui, ctx);
        self.status_bar(ui);
        match self.tab {
            Tab::Verdicts => {
                self.verdict_list(ui);
                self.verdict_detail(ui);
            }
            Tab::Quarantine => self.quarantine_tab(ui),
            Tab::Options => self.options(ui),
        }
    }

    fn header(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        egui::Panel::top("header")
            .frame(Frame::new().fill(BAR).inner_margin(Margin::symmetric(20, 12)))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("DoubleAgent").size(22.0).strong());
                    ui.add_space(16.0);
                    ui.selectable_value(&mut self.tab, Tab::Verdicts, "Verdicts");
                    if ui.selectable_value(&mut self.tab, Tab::Quarantine, "Quarantine").clicked() {
                        self.refresh_quarantine();
                    }
                    ui.selectable_value(&mut self.tab, Tab::Options, "Options");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Quit").clicked() {
                            self.quit(ctx);
                        }
                        if ui.button(if self.paused { "Resume" } else { "Pause" }).clicked() {
                            self.set_paused(!self.paused);
                        }
                        if ui.button("Scan now").clicked() {
                            self.scan_now();
                        }
                    });
                });
            });
    }

    fn status_bar(&mut self, ui: &mut Ui) {
        let status = self.status();
        egui::Panel::bottom("status")
            .frame(Frame::new().fill(BAR).inner_margin(Margin::symmetric(20, 8)))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let (dot, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), Sense::hover());
                    let [r, g, b] = status.rgb();
                    ui.painter().circle_filled(dot.center(), 5.0, Color32::from_rgb(r, g, b));
                    ui.label(RichText::new(&self.status).size(13.0).color(ui.visuals().weak_text_color()));
                });
            });
    }

    fn verdict_list(&mut self, ui: &mut Ui) {
        let mut clicked = None;
        egui::Panel::left("verdicts")
            .resizable(true)
            .default_size(400.0)
            .size_range(300.0..=620.0)
            .frame(Frame::new().fill(PANEL).inner_margin(Margin::same(18)))
            .show(ui, |ui| {
                ui.label(RichText::new("Latest verdicts").size(18.0).strong());
                ui.label(
                    RichText::new(format!("{} instruction files", self.reports.len()))
                        .size(13.0)
                        .color(ui.visuals().weak_text_color()),
                );
                ui.add_space(8.0);
                egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 8.0;
                    if self.reports.is_empty() {
                        ui.label("No agent instruction files found yet.");
                    }
                    for (index, report) in self.reports.iter().enumerate() {
                        if report_card(ui, report, self.selected == Some(index)).clicked() {
                            clicked = Some(index);
                        }
                    }
                    ui.add_space(4.0);
                });
            });
        if clicked.is_some() {
            self.selected = clicked;
        }
    }

    fn verdict_detail(&mut self, ui: &mut Ui) {
        let report = self.selected.and_then(|index| self.reports.get(index)).cloned();
        egui::CentralPanel::default()
            .frame(Frame::new().fill(PANEL).inner_margin(Margin::symmetric(24, 18)))
            .show(ui, |ui| {
                let Some(report) = report else {
                    ui.vertical_centered(|ui| {
                        ui.add_space(110.0);
                        ui.label(RichText::new("Your agent files are being monitored").size(20.0));
                        ui.label(
                            RichText::new("Choose a verdict to review its findings and provenance.").color(ui.visuals().weak_text_color()),
                        );
                    });
                    return;
                };
                let color = severity_color(report.severity);
                egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(report.path.file_name().unwrap_or_default().to_string_lossy())
                                .size(24.0)
                                .strong(),
                        );
                        pill(ui, &report.severity.as_str().to_uppercase(), color);
                    });
                    ui.label(
                        RichText::new(report.path.display().to_string())
                            .monospace()
                            .size(12.0)
                            .color(ui.visuals().weak_text_color()),
                    );
                    ui.add_space(6.0);
                    ui.horizontal_wrapped(|ui| {
                        stat_tile(ui, "SCORE", report.scores.final_score, color);
                        stat_tile(ui, "CONTENT", report.scores.content, ui.visuals().text_color());
                        stat_tile(ui, "PROVENANCE", report.scores.provenance, ui.visuals().text_color());
                        stat_tile(ui, "SHADOW", report.scores.shadow, ui.visuals().text_color());
                    });
                    findings_view(ui, &report);
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Show in folder").clicked() {
                            if let Err(error) = open_path(&report.path) {
                                self.status = format!("Could not open file: {error}");
                            }
                        }
                        if ui
                            .button("Quarantine file")
                            .on_hover_text("Move this file to the quarantine folder. You can restore it from the Quarantine tab.")
                            .clicked()
                        {
                            self.quarantine_selected(&report);
                        }
                    });
                    ui.add_space(8.0);
                });
            });
    }

    fn options(&mut self, ui: &mut Ui) {
        let mut action = None;
        let dirty = self.draft.to_config().to_toml().ok() != self.cfg.to_toml().ok();
        egui::Panel::bottom("options_actions")
            .frame(Frame::new().fill(BAR).inner_margin(Margin::symmetric(20, 10)))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if ui.add_enabled(dirty, egui::Button::new("Save & apply")).clicked() {
                        action = Some(OptionsAction::Save);
                    }
                    if ui.add_enabled(dirty, egui::Button::new("Revert")).clicked() {
                        action = Some(OptionsAction::Revert);
                    }
                    ui.separator();
                    if ui.button("Import…").clicked() {
                        action = Some(OptionsAction::Import);
                    }
                    if ui.button("Export…").clicked() {
                        action = Some(OptionsAction::Export);
                    }
                    if ui.button("Reset to defaults").clicked() {
                        action = Some(OptionsAction::Reset);
                    }
                    ui.add_space(8.0);
                    if let Some((ok, note)) = &self.options_note {
                        let color = if *ok { ACCENT } else { severity_color(Severity::Critical) };
                        ui.label(RichText::new(note).color(color));
                    } else if dirty {
                        hint(ui, "Unsaved changes");
                    }
                });
            });
        egui::CentralPanel::default()
            .frame(Frame::new().fill(PANEL).inner_margin(Margin::symmetric(24, 18)))
            .show(ui, |ui| {
                egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                    ui.set_max_width(820.0);
                    options_form(ui, &mut self.draft, &mut action);
                });
            });
        if let Some(action) = action {
            self.run_options_action(action);
        }
    }

    fn quarantine_selected(&mut self, report: &Report) {
        let result = Store::open(&self.db_path).and_then(|store| {
            let (id, _) = doubleagent::policy::quarantine(&report.path, &report.sha256, &self.cfg, &store, report, true)?;
            store.mark_missing(&report.path.to_string_lossy())?;
            Ok(id)
        });
        match result {
            Ok(id) => {
                self.reports.retain(|r| r.path != report.path);
                self.selected = None;
                self.status = format!("Quarantined {} manually (#{id})", report.path.display());
                self.refresh_quarantine();
            }
            Err(error) => self.status = format!("Could not quarantine: {error:#}"),
        }
    }

    fn refresh_quarantine(&mut self) {
        match Store::open(&self.db_path).and_then(|store| store.list_quarantine()) {
            Ok(rows) => self.quarantine = rows.into_iter().filter(|row| !row.restored).collect(),
            Err(error) => self.quarantine_note = Some((false, format!("{error:#}"))),
        }
    }

    /// Put a file back. With `whitelist`, pin its exact content first so it isn't re-quarantined.
    fn restore_entry(&mut self, row: &QuarantineRow, whitelist: bool) -> Result<String> {
        let store = Store::open(&self.db_path)?;
        if whitelist {
            store.add_allow(
                "pin",
                &row.original_path,
                Some(&row.sha256),
                Some("whitelisted from the Quarantine tab"),
            )?;
            store.audit("allow", &format!("pin {} (from quarantine #{})", row.original_path, row.id))?;
        }
        let path = doubleagent::policy::restore(row.id, &store)?;
        Ok(format!(
            "Restored {}{}",
            path.display(),
            if whitelist { " and whitelisted it" } else { "" }
        ))
    }

    fn quarantine_tab(&mut self, ui: &mut Ui) {
        let dir = doubleagent::policy::quarantine_dir(&self.cfg);
        let mut restore = None;
        egui::CentralPanel::default()
            .frame(Frame::new().fill(PANEL).inner_margin(Margin::symmetric(24, 18)))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Quarantined files").size(18.0).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Open quarantine folder").clicked() {
                            self.quarantine_note = open_dir(&dir).err().map(|e| (false, format!("{e:#}")));
                        }
                        if ui.button("Refresh").clicked() {
                            self.refresh_quarantine();
                        }
                    });
                });
                ui.label(
                    RichText::new(format!("{} · {} file(s)", dir.display(), self.quarantine.len()))
                        .size(12.0)
                        .color(ui.visuals().weak_text_color()),
                );
                if let Some((ok, note)) = &self.quarantine_note {
                    let color = if *ok { ACCENT } else { severity_color(Severity::Critical) };
                    ui.label(RichText::new(note).color(color));
                }
                ui.add_space(6.0);
                egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                    if self.quarantine.is_empty() {
                        ui.label("Nothing is quarantined. Files are only moved here when `quarantine_at` is set and a file reaches it.");
                    }
                    for row in &self.quarantine {
                        card().show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            let name = Path::new(&row.original_path)
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .into_owned();
                            ui.label(RichText::new(name).strong().size(15.0));
                            ui.label(
                                RichText::new(&row.original_path)
                                    .monospace()
                                    .size(12.0)
                                    .color(ui.visuals().weak_text_color()),
                            );
                            hint(
                                ui,
                                &format!(
                                    "Quarantined {} · #{} · sha256 {}",
                                    row.ts,
                                    row.id,
                                    &row.sha256[..row.sha256.len().min(12)]
                                ),
                            );
                            ui.horizontal(|ui| {
                                pill(
                                    ui,
                                    if row.manual { "MANUAL" } else { "AUTOMATIC" },
                                    if row.manual { Color32::from_rgb(120, 144, 220) } else { ACCENT },
                                );
                                if let Some(report) = &row.report {
                                    pill(ui, &report.severity.as_str().to_uppercase(), severity_color(report.severity));
                                    hint(ui, &format!("score {}", report.scores.final_score));
                                }
                            });
                            match &row.report {
                                Some(report) => {
                                    egui::CollapsingHeader::new("Why was this quarantined?")
                                        .id_salt(row.id)
                                        .show(ui, |ui| findings_view(ui, report));
                                }
                                None => hint(ui, "No findings were recorded for this file."),
                            }
                            ui.horizontal(|ui| {
                                if ui.button("Unquarantine").clicked() {
                                    restore = Some((row.clone(), false));
                                }
                                if ui.button("Unquarantine & whitelist").clicked() {
                                    restore = Some((row.clone(), true));
                                }
                            });
                        });
                        ui.add_space(4.0);
                    }
                });
            });
        if restore.is_some() {
            self.confirm_restore = restore;
        }
        self.confirm_dialog(ui.ctx());
    }

    fn confirm_dialog(&mut self, ctx: &egui::Context) {
        let Some((row, whitelist)) = self.confirm_restore.clone() else {
            return;
        };
        let mut decision = None;
        egui::Modal::new(egui::Id::unique("confirm_restore")).show(ctx, |ui| {
            ui.set_width(440.0);
            ui.label(RichText::new("⚠ Restore this file?").size(18.0).strong().color(severity_color(Severity::High)));
            ui.add_space(4.0);
            ui.label(&row.original_path);
            ui.add_space(4.0);
            ui.label("DoubleAgent flagged this file as risky. Restoring it puts it back where AI agents will read it.");
            if whitelist {
                ui.label("It will also be whitelisted: this exact content (by hash) will no longer be reported or quarantined. If the file changes, it is checked again.");
            } else {
                ui.label("Without whitelisting, it may be quarantined again the next time it is scanned.");
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let label = if whitelist { "Restore & whitelist" } else { "Restore" };
                if ui.button(RichText::new(label).color(severity_color(Severity::High))).clicked() {
                    decision = Some(true);
                }
                if ui.button("Cancel").clicked() {
                    decision = Some(false);
                }
            });
        });
        match decision {
            Some(true) => {
                self.quarantine_note = Some(match self.restore_entry(&row, whitelist) {
                    Ok(note) => (true, note),
                    Err(error) => (false, format!("{error:#}")),
                });
                self.confirm_restore = None;
                self.refresh_quarantine();
            }
            Some(false) => self.confirm_restore = None,
            None => {}
        }
    }

    fn run_options_action(&mut self, action: OptionsAction) {
        let result: Result<String> = (|| match action {
            OptionsAction::Save => {
                self.save_options()?;
                Ok(format!("Saved to {}", self.config_path.display()))
            }
            OptionsAction::Revert => {
                self.draft = Draft::new(&self.cfg);
                Ok("Reverted to the saved settings".into())
            }
            OptionsAction::Import => {
                let Some(path) = rfd::FileDialog::new().add_filter("DoubleAgent config", &["toml"]).pick_file() else {
                    return Ok(String::new());
                };
                let (cfg, _) = Config::load(Some(&path))?;
                self.draft = Draft::new(&cfg);
                Ok(format!("Imported {} · Save & apply to use it", path.display()))
            }
            OptionsAction::Export => {
                let cfg = self.draft.to_config();
                cfg.validate()?;
                let Some(path) = rfd::FileDialog::new()
                    .add_filter("DoubleAgent config", &["toml"])
                    .set_file_name("doubleagent-config.toml")
                    .save_file()
                else {
                    return Ok(String::new());
                };
                std::fs::write(&path, cfg.to_toml()?).with_context(|| format!("writing {}", path.display()))?;
                Ok(format!("Exported to {}", path.display()))
            }
            OptionsAction::Reset => {
                self.draft = Draft::new(&Config::default());
                Ok("Defaults loaded · Save & apply to use them".into())
            }
            OptionsAction::TestNotification => {
                doubleagent::policy::notify("This is a test notification from DoubleAgent.")?;
                Ok("Test notification sent".into())
            }
        })();
        self.options_note = match result {
            Ok(note) if note.is_empty() => None,
            Ok(note) => Some((true, note)),
            Err(error) => Some((false, format!("{error:#}"))),
        };
    }
}

fn options_form(ui: &mut Ui, draft: &mut Draft, action: &mut Option<OptionsAction>) {
    let can_start_on_login = startup::shortcut_path().is_some();
    section(ui, "Startup", |ui| {
        ui.add_enabled(
            can_start_on_login,
            egui::Checkbox::new(&mut draft.cfg.gui.run_on_startup, "Run on startup"),
        );
        hint(
            ui,
            if can_start_on_login {
                "Adds a shortcut to your Startup folder so DoubleAgent starts when you sign in."
            } else {
                "Not supported on this platform yet."
            },
        );
        ui.checkbox(&mut draft.cfg.gui.show_ui_on_startup, "Show UI on startup");
        hint(ui, "When off, DoubleAgent starts minimised in the system tray.");
    });

    section(ui, "Notifications & actions", |ui| {
        egui::Grid::new("notify").num_columns(2).spacing([16.0, 10.0]).show(ui, |ui| {
            ui.label("Notify at or above");
            ui.horizontal(|ui| {
                severity_picker(ui, "notify_at", &mut draft.cfg.policy.notify_at, true);
                if ui.button("Send test").clicked() {
                    *action = Some(OptionsAction::TestNotification);
                }
            });
            ui.end_row();
            ui.label("Run hook at or above");
            severity_picker(ui, "hook_at", &mut draft.cfg.policy.hook_at, true);
            ui.end_row();
            ui.label("Quarantine at or above");
            severity_picker(ui, "quarantine_at", &mut draft.cfg.policy.quarantine_at, true);
            ui.end_row();
            ui.label("Quarantine folder");
            ui.add(
                egui::TextEdit::singleline(&mut draft.quarantine_dir)
                    .hint_text("default")
                    .desired_width(360.0),
            );
            ui.end_row();
        });
        hint(
            ui,
            "Notifications fire once for each new or changed file that reaches the threshold. Quarantine moves files, never deletes them.",
        );
    });

    section(ui, "Scanning", |ui| {
        ui.label("Folders to watch (one per line; empty = your home folder)");
        list_editor(ui, &mut draft.roots, 3);
        ui.label("Folder names to skip");
        list_editor(ui, &mut draft.exclude_dirs, 4);
        let mut max_kb = draft.cfg.scan.max_file_size / 1024;
        ui.horizontal(|ui| {
            ui.label("Largest file to read");
            ui.add(egui::DragValue::new(&mut max_kb).range(1..=65536).suffix(" KB"));
        });
        draft.cfg.scan.max_file_size = max_kb * 1024;
        ui.checkbox(&mut draft.cfg.scan.follow_symlinks, "Follow symlinks and junctions");
        ui.checkbox(&mut draft.cfg.scan.skip_network_mounts, "Skip network drives");
        ui.checkbox(&mut draft.cfg.scan.skip_cloud_placeholders, "Skip online-only cloud files");
    });

    section(ui, "Monitoring", |ui| {
        egui::Grid::new("watch").num_columns(2).spacing([16.0, 10.0]).show(ui, |ui| {
            ui.label("Settle time after a change");
            ui.add(
                egui::DragValue::new(&mut draft.cfg.watch.debounce_ms)
                    .range(100..=60_000)
                    .suffix(" ms"),
            );
            ui.end_row();
            ui.label("Full re-scan every");
            ui.add(
                egui::DragValue::new(&mut draft.cfg.watch.reconcile_minutes)
                    .range(1..=1440)
                    .suffix(" min"),
            );
            ui.end_row();
            ui.label("Polling interval");
            ui.add(
                egui::DragValue::new(&mut draft.cfg.watch.poll_interval_secs)
                    .range(2..=3600)
                    .suffix(" s"),
            );
            ui.end_row();
        });
        ui.checkbox(&mut draft.cfg.watch.force_polling, "Poll instead of using file-system events");
    });

    section(ui, "Scoring", |ui| {
        let t = &mut draft.cfg.policy.thresholds;
        egui::Grid::new("thresholds").num_columns(2).spacing([16.0, 10.0]).show(ui, |ui| {
            for (label, value) in [
                ("Low from score", &mut t.low),
                ("Medium from score", &mut t.medium),
                ("High from score", &mut t.high),
                ("Critical from score", &mut t.critical),
            ] {
                ui.label(label);
                ui.add(egui::DragValue::new(value).range(1..=100));
                ui.end_row();
            }
        });
        hint(ui, "Each threshold must be higher than the one before, up to 100.");
        ui.add_space(4.0);
        ui.label("Disabled rule IDs (one per line)");
        list_editor(ui, &mut draft.disabled_rules, 2);
        ui.label("Trusted domains");
        list_editor(ui, &mut draft.trusted_domains, 4);
        ui.label("Trusted git remotes");
        list_editor(ui, &mut draft.trusted_remotes, 2);
        ui.horizontal(|ui| {
            ui.label("Count a file as recent for");
            ui.add(
                egui::DragValue::new(&mut draft.cfg.provenance.recent_hours)
                    .range(1..=8760)
                    .suffix(" h"),
            );
        });
        ui.checkbox(&mut draft.cfg.provenance.use_git, "Use git for tracked / commit information");
    });

    section(ui, "Output", |ui| {
        egui::Grid::new("output").num_columns(2).spacing([16.0, 10.0]).show(ui, |ui| {
            ui.label("JSON Lines log");
            ui.add(
                egui::TextEdit::singleline(&mut draft.jsonl_path)
                    .hint_text("off")
                    .desired_width(360.0),
            );
            ui.end_row();
            ui.label("Webhook URL");
            ui.add(
                egui::TextEdit::singleline(&mut draft.webhook_url)
                    .hint_text("off")
                    .desired_width(360.0),
            );
            ui.end_row();
            ui.label("Webhook at or above");
            let mut severity = Some(draft.cfg.output.webhook_min_severity);
            severity_picker(ui, "webhook_min", &mut severity, false);
            if let Some(severity) = severity {
                draft.cfg.output.webhook_min_severity = severity;
            }
            ui.end_row();
        });
    });
}
