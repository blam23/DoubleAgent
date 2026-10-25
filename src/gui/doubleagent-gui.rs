#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod icon;
mod options;
mod views;

use anyhow::{Context as _, Result};
use clap::Parser;
use doubleagent::config::Config;
use doubleagent::engine::{Engine, RunOptions};
use doubleagent::model::{Report, Severity};
use doubleagent::scanner::Matcher;
use doubleagent::startup;
use doubleagent::store::Store;
use doubleagent::watch::{self, WatchCommand};
use eframe::egui;
use icon::Status;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

#[derive(Parser)]
#[command(name = "doubleagent-gui", version, about = "DoubleAgent desktop monitor")]
struct Args {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    db: Option<PathBuf>,
    paths: Vec<PathBuf>,
}

enum AppMessage {
    /// `alerts` counts reports that raised an OS notification in this pass.
    Update {
        reports: Vec<Report>,
        label: String,
        alerts: usize,
        notify_errors: Vec<String>,
    },
    Error(String),
}

/// What the tray and its menu report back to the window.
enum TrayEvent {
    Open,
    Menu(MenuId),
}

/// A running monitor thread and the channels to talk to it.
struct Monitor {
    messages: Receiver<AppMessage>,
    commands: Sender<WatchCommand>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Verdicts,
    Quarantine,
    Options,
}

struct TrayHandle {
    icon: TrayIcon,
    pause_item: MenuItem,
    ids: [MenuId; 4],
    shown: Option<Status>,
}

struct DoubleAgentApp {
    reports: Vec<Report>,
    selected: Option<usize>,
    tab: Tab,
    status: String,
    paused: bool,
    /// False once the monitor thread has failed.
    monitor_alive: bool,
    unread: bool,
    visible: bool,
    allow_exit: bool,
    monitor: Monitor,
    tray: Option<TrayHandle>,
    tray_events: Receiver<TrayEvent>,
    config_path: PathBuf,
    db_path: PathBuf,
    cli_paths: Vec<PathBuf>,
    cfg: Config,
    draft: options::Draft,
    options_note: Option<(bool, String)>,
    quarantine: Vec<doubleagent::store::QuarantineRow>,
    /// Entry awaiting confirmation, and whether it is also being whitelisted.
    confirm_restore: Option<(doubleagent::store::QuarantineRow, bool)>,
    quarantine_note: Option<(bool, String)>,
}

impl DoubleAgentApp {
    fn status(&self) -> Status {
        if !self.monitor_alive || self.paused {
            Status::Stopped
        } else if self.unread {
            Status::Unread
        } else {
            Status::Running
        }
    }

    fn handle_events(&mut self, ctx: &egui::Context) {
        while let Ok(message) = self.monitor.messages.try_recv() {
            match message {
                AppMessage::Update {
                    reports,
                    label,
                    alerts,
                    notify_errors,
                } => {
                    self.reports = reports;
                    self.status = format!("Monitoring · {label} · {} files", self.reports.len());
                    if let Some(error) = notify_errors.first() {
                        self.status = format!("Could not show notification: {error}");
                    }
                    self.unread |= alerts > 0;
                }
                AppMessage::Error(error) => {
                    self.monitor_alive = false;
                    self.status = format!("Monitor error: {error}");
                }
            }
        }
        while let Ok(event) = self.tray_events.try_recv() {
            match event {
                TrayEvent::Open => self.show_window(ctx),
                TrayEvent::Menu(id) => self.menu_action(&id, ctx),
            }
        }
        if self.visible && ctx.input(|input| input.viewport().focused == Some(true)) {
            self.unread = false;
        }
    }

    fn menu_action(&mut self, id: &MenuId, ctx: &egui::Context) {
        let Some(ids) = self.tray.as_ref().map(|t| t.ids.clone()) else {
            return;
        };
        if *id == ids[0] {
            self.show_window(ctx);
        } else if *id == ids[1] {
            self.scan_now();
        } else if *id == ids[2] {
            self.set_paused(!self.paused);
        } else if *id == ids[3] {
            self.quit(ctx);
        }
    }

    fn show_window(&mut self, ctx: &egui::Context) {
        self.visible = true;
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    fn quit(&mut self, ctx: &egui::Context) {
        self.allow_exit = true;
        let _ = self.monitor.commands.send(WatchCommand::Quit);
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }

    fn set_paused(&mut self, paused: bool) {
        self.paused = paused;
        let _ = self
            .monitor
            .commands
            .send(if paused { WatchCommand::Pause } else { WatchCommand::Resume });
        self.status = if paused {
            "Monitoring paused"
        } else {
            "Monitoring resumed · checking for changes…"
        }
        .into();
        if let Some(tray) = &self.tray {
            tray.pause_item
                .set_text(if paused { "Resume monitoring" } else { "Pause monitoring" });
        }
    }

    fn scan_now(&mut self) {
        self.paused = false;
        let _ = self.monitor.commands.send(WatchCommand::ScanNow);
        self.status = "Scanning configured folders…".into();
        if let Some(tray) = &self.tray {
            tray.pause_item.set_text("Pause monitoring");
        }
    }

    /// Keep the tray icon and tooltip in step with the monitor.
    fn sync_tray(&mut self) {
        let status = self.status();
        let Some(tray) = &mut self.tray else { return };
        if tray.shown == Some(status) {
            return;
        }
        if let Ok(icon) = tray_icon_for(status) {
            let _ = tray.icon.set_icon(Some(icon));
        }
        let _ = tray.icon.set_tooltip(Some(format!("DoubleAgent · {}", status.label())));
        tray.shown = Some(status);
    }

    /// Write the config, apply the startup setting and restart the monitor with it.
    fn save_options(&mut self) -> Result<()> {
        let cfg = self.draft.to_config();
        cfg.validate()?;
        if let Some(dir) = self.config_path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        std::fs::write(&self.config_path, cfg.to_toml()?).with_context(|| format!("writing {}", self.config_path.display()))?;
        startup::set_enabled(cfg.gui.run_on_startup, &std::env::current_exe()?)?;
        let roots = roots(&self.cli_paths, &cfg)?;
        let monitor = spawn_monitor(&cfg, &self.db_path, roots)?;
        let _ = std::mem::replace(&mut self.monitor, monitor).commands.send(WatchCommand::Quit);
        self.cfg = cfg;
        self.paused = false;
        self.monitor_alive = true;
        self.status = "Settings saved · monitor restarted".into();
        if let Some(tray) = &self.tray {
            tray.pause_item.set_text("Pause monitoring");
        }
        Ok(())
    }
}

impl eframe::App for DoubleAgentApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.handle_events(&ctx);
        self.sync_tray();
        if ctx.input(|input| input.viewport().close_requested()) && !self.allow_exit && self.tray.is_some() {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            self.visible = false;
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(250));
        self.show(ui, &ctx);
    }
}

fn tray_icon_for(status: Status) -> Result<Icon> {
    let icon = icon::tray(status)?;
    Icon::from_rgba(icon.pixels, icon.width, icon.height).context("creating tray icon")
}

fn make_tray(events: Sender<TrayEvent>, ctx: egui::Context) -> Result<TrayHandle> {
    let menu = Menu::new();
    let show = MenuItem::with_id("show", "Show UI", true, None);
    let scan = MenuItem::with_id("scan", "Scan now", true, None);
    let pause = MenuItem::with_id("pause", "Pause monitoring", true, None);
    let quit = MenuItem::with_id("quit", "Quit", true, None);
    menu.append_items(&[&show, &scan, &pause, &quit])?;

    // Only a completed left click opens the window; hover, move and button-down events are ignored.
    let tray_events = events.clone();
    let tray_ctx = ctx.clone();
    TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
        let open = matches!(
            event,
            TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } | TrayIconEvent::DoubleClick {
                button: MouseButton::Left,
                ..
            }
        );
        if open {
            let _ = tray_events.send(TrayEvent::Open);
            tray_ctx.request_repaint();
        }
    }));
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        let _ = events.send(TrayEvent::Menu(event.id));
        ctx.request_repaint();
    }));

    let icon = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(false)
        .with_tooltip("DoubleAgent · monitoring")
        .with_icon(tray_icon_for(Status::Running)?)
        .build()?;
    let ids = [show.id().clone(), scan.id().clone(), pause.id().clone(), quit.id().clone()];
    Ok(TrayHandle {
        icon,
        pause_item: pause,
        ids,
        shown: Some(Status::Running),
    })
}

fn roots(paths: &[PathBuf], cfg: &Config) -> Result<Vec<PathBuf>> {
    let roots = if !paths.is_empty() {
        paths.to_vec()
    } else if !cfg.scan.roots.is_empty() {
        cfg.scan.roots.clone()
    } else {
        vec![dirs::home_dir().context("no home folder; pass a scan path")?]
    };
    Ok(roots
        .into_iter()
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                std::env::current_dir().unwrap_or_default().join(path)
            }
        })
        .collect())
}

fn spawn_monitor(cfg: &Config, db_path: &Path, roots: Vec<PathBuf>) -> Result<Monitor> {
    let (message_tx, messages) = mpsc::channel();
    let (commands, command_rx) = mpsc::channel();
    let cfg = cfg.clone();
    let db_path = db_path.to_path_buf();
    thread::Builder::new().name("doubleagent-monitor".into()).spawn(move || {
        let result = (|| -> Result<()> {
            let store = Store::open(&db_path)?;
            let matcher = Matcher::new(&cfg.scan)?;
            let engine = Engine::new(
                &cfg,
                &store,
                &matcher,
                RunOptions {
                    apply_actions: true,
                    skip_unchanged: true,
                },
            )?;
            watch::run_controlled(&engine, &roots, command_rx, |outcome, label| {
                let reports = store.latest_reports(Severity::Info).unwrap_or_else(|_| outcome.reports.clone());
                let actions = || outcome.reports.iter().flat_map(|r| &r.actions);
                let _ = message_tx.send(AppMessage::Update {
                    reports,
                    label: label.to_owned(),
                    alerts: actions().filter(|a| *a == "notified").count(),
                    notify_errors: actions()
                        .filter_map(|a| a.strip_prefix("notify failed: "))
                        .map(str::to_owned)
                        .collect(),
                });
            })
        })();
        if let Err(error) = result {
            let _ = message_tx.send(AppMessage::Error(format!("{error:#}")));
        }
    })?;
    Ok(Monitor { messages, commands })
}

fn main() -> Result<()> {
    let args = Args::parse();
    let (cfg, config_path) = Config::load(args.config.as_deref())?;
    let db_path = args.db.unwrap_or_else(doubleagent::config::default_db_path);
    let store = Store::open(&db_path)?;
    let reports = store.latest_reports(Severity::Info)?;
    // Let editor integrations see this app's verdicts. If a daemon already owns the port, that is fine.
    let _ = doubleagent::service::start(db_path.clone());
    let monitor = spawn_monitor(&cfg, &db_path, roots(&args.paths, &cfg)?)?;

    // Keep the startup shortcut in line with the setting (and pointing at this executable).
    // Debug builds leave it alone so a dev build never registers itself.
    if !cfg!(debug_assertions) {
        if let Ok(exe) = std::env::current_exe() {
            let _ = startup::set_enabled(cfg.gui.run_on_startup, &exe);
        }
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("DoubleAgent")
            .with_inner_size([1120.0, 740.0])
            .with_min_inner_size([820.0, 560.0])
            .with_visible(cfg.gui.show_ui_on_startup),
        ..Default::default()
    };
    let mut options = options;
    if let Ok(icon) = icon::window() {
        options.viewport = options.viewport.with_icon(Arc::new(egui::IconData {
            rgba: icon.pixels,
            width: icon.width,
            height: icon.height,
        }));
    }
    let show_on_start = cfg.gui.show_ui_on_startup;
    eframe::run_native(
        "DoubleAgent",
        options,
        Box::new(move |cc| {
            views::apply_theme(&cc.egui_ctx);
            let (event_tx, tray_events) = mpsc::channel();
            let mut status = "Starting monitor…".to_owned();
            let tray = match make_tray(event_tx, cc.egui_ctx.clone()) {
                Ok(tray) => Some(tray),
                Err(error) => {
                    status = format!("System tray unavailable: {error:#}");
                    None
                }
            };
            Ok(Box::new(DoubleAgentApp {
                reports,
                selected: None,
                tab: Tab::Verdicts,
                status,
                paused: false,
                monitor_alive: true,
                unread: false,
                visible: show_on_start,
                allow_exit: false,
                monitor,
                tray,
                tray_events,
                config_path,
                db_path,
                cli_paths: args.paths,
                draft: options::Draft::new(&cfg),
                cfg,
                options_note: None,
                quarantine: Vec::new(),
                confirm_restore: None,
                quarantine_note: None,
            }))
        }),
    )?;
    Ok(())
}
