#![cfg_attr(windows, windows_subsystem = "windows")]

//! Yeager application: Slint UI, system-tray lifecycle and orchestration of the
//! `erwin` (TCP + config) and `hange` (DoH) engines. See the Technical Design
//! Document for the role of each crate.

slint::include_modules!();

mod engine;
#[cfg(windows)]
mod platform;
mod updater;

use common::lang::{self, tr};
use common::{t, Config, Congestion, DohProvider, Language, Scope, TransportProfile};
use erwin::config;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel, Weak};
use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How often a running Yeager looks for a new release.
const UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
/// How often the network card on the home page looks up the addresses again
/// while the window shows.
const NETWORK_REFRESH: Duration = Duration::from_secs(10 * 60);
/// How long the domain sheets wait after the last edit before writing config.json.
const DOMAIN_SAVE_DEBOUNCE: Duration = Duration::from_millis(500);
/// Quiet period after the last geometry change before a poll may persist it.
/// Ensures only settled normal geometry reaches the file, never in-progress
/// drag samples.
const GEOMETRY_QUIET: Duration = Duration::from_millis(800);
/// How often the geometry poll checks for settled normal bounds.
const GEOMETRY_POLL: Duration = Duration::from_millis(250);
/// Delay after first presentation before latching initialization and
/// committing the validated pair (lets native bounds settle).
const GEOMETRY_SETTLE: Duration = Duration::from_millis(800);

/// In-memory settled-geometry state, held separately from live bounds.
///
/// `last_known_good` is the validated normal rectangle. Live minimized,
/// maximized, transient, DPI-transitioning or work-area-constrained samples
/// never overwrite it. `initialized` is latched from real presentation, not
/// hardcoded at the call sites.
#[derive(Debug, Clone)]
pub struct GeometryTracker {
    pub last_known_good: Option<[u32; 2]>,
    pub initialized: bool,
    pub last_scale: Option<f32>,
    pub last_work_area: Option<(f32, f32)>,
    pub pending: Option<[u32; 2]>,
    pub pending_since: Option<Instant>,
}

impl GeometryTracker {
    pub fn new(last_known_good: Option<[u32; 2]>) -> Self {
        Self {
            last_known_good,
            initialized: false,
            last_scale: None,
            last_work_area: None,
            pending: None,
            pending_since: None,
        }
    }
}

/// Whether a live sample is only a work-area-constrained snapshot of a
/// still-valid `last_known_good` (and must not overwrite it).
pub fn is_work_area_constrained_snapshot(
    live: [u32; 2],
    last_good: Option<[u32; 2]>,
    work_area: Option<(f32, f32)>,
) -> bool {
    let (Some([lw, lh]), Some((ww, wh))) = (last_good, work_area) else {
        return false;
    };
    if live == [lw, lh] {
        return false;
    }
    if !common::is_valid_window_size_u32(lw, lh) {
        return false;
    }
    let (cw, ch) = common::clamp_window_size_to_work_area(lw as f32, lh as f32, ww, wh);
    live == [cw.round() as u32, ch.round() as u32]
}

/// Runs a blocking operation off the UI thread and reports the result through a
/// closure back on the UI thread.
fn spawn<T: Send + 'static>(
    ui: Weak<MainWindow>,
    work: impl FnOnce() -> T + Send + 'static,
    done: impl FnOnce(MainWindow, T) + Send + 'static,
) {
    std::thread::spawn(move || {
        let result = work();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = ui.upgrade() {
                done(ui, result);
            }
        });
    });
}

fn scope_from_index(i: i32) -> Scope {
    match i {
        1 => Scope::HostList,
        _ => Scope::All,
    }
}

fn congestion_from_index(i: i32) -> Congestion {
    match i {
        1 => Congestion::Bbr2,
        2 => Congestion::Cubic,
        3 => Congestion::Ctcp,
        _ => Congestion::Auto,
    }
}

fn congestion_index(c: Congestion) -> i32 {
    match c {
        Congestion::Auto => 0,
        Congestion::Bbr2 => 1,
        Congestion::Cubic => 2,
        Congestion::Ctcp => 3,
    }
}

/// The DNS provider row selected on the DNS page: -1 is Auto, then
/// [`DohProvider::ALL`] in order.
fn provider_index(cfg: &Config) -> i32 {
    if cfg.doh_auto {
        -1
    } else {
        DohProvider::ALL.iter().position(|&p| p == cfg.doh_provider).unwrap_or(0) as i32
    }
}

fn dns_choice(cfg: &Config) -> hange::Choice {
    if cfg.doh_auto {
        hange::Choice::Auto
    } else {
        hange::Choice::Fixed(cfg.doh_provider)
    }
}

fn choice_label(choice: hange::Choice) -> &'static str {
    match choice {
        hange::Choice::Fixed(p) => p.label(),
        hange::Choice::Auto => tr("Tự động", "Auto"),
    }
}

fn apply_config_to_ui(ui: &MainWindow, cfg: &Config) {
    ui.set_scope(match cfg.scope {
        Scope::All => 0,
        Scope::HostList => 1,
    });
    ui.set_congestion_sel(congestion_index(cfg.congestion));
    ui.set_tcp_enabled(cfg.tcp_enabled);
    ui.set_low_latency(cfg.low_latency);
    ui.set_doh_enabled(cfg.doh_enabled);
    ui.set_doh_provider(provider_index(cfg));
    ui.set_doh_http3(cfg.doh_http3);
    set_hosts(ui, cfg);
    ui.set_game_protection(cfg.compatibility_mode_enabled);
    set_excluded_domains(ui, cfg);
    ui.set_transport_profile(transport_profile_index(cfg.transport_profile));
    ui.set_connect_on_launch(cfg.connect_on_launch);
    ui.set_launch_login(cfg.launch_at_login);
    ui.set_dark(cfg.dark);
    if let Some(c) = parse_hex_color(&cfg.accent) {
        ui.global::<Theme>().set_accent(c);
    }
    ui.set_check_updates(cfg.check_updates);
    ui.set_english(lang::is_en());
}

fn main() -> Result<(), slint::PlatformError> {
    // Run by the uninstaller after it has closed the app: put back what Yeager
    // changed in Windows (TCP, DNS, the logon task) and exit without a window.
    if std::env::args().any(|a| a == "--cleanup") {
        let _ = erwin::restore();
        let _ = erwin::latency::restore();
        hange::clean_up_leftovers();
        let _ = erwin::set_launch_at_login(false, &Default::default());
        return Ok(());
    }

    #[cfg(windows)]
    {
        let build = platform::get_windows_build();
        if build > 0 && build < 20348 {
            // Safety: if the user upgraded to a version requiring Win11 while having
            // active configurations or backups from a previous Yeager run, restore them cleanly.
            let _ = erwin::restore();
            let _ = erwin::latency::restore();
            hange::clean_up_leftovers();
            let _ = erwin::set_launch_at_login(false, &Default::default());

            platform::show_unsupported_os_dialog(build);
            return Ok(());
        }
    }

    // Started by an update: the previous exe is on its way out.
    let updated = std::env::args().any(|a| a == updater::UPDATED_ARG);
    let resume = std::env::args().any(|a| a == updater::CONNECT_ARG);
    updater::finish_previous_update(updated);

    #[cfg(windows)]
    let instance_guard = match platform::ensure_single_instance(updated) {
        platform::SingleInstanceDecision::Proceed(guard) => guard,
        platform::SingleInstanceDecision::AlreadyRunning => return Ok(()),
    };

    let ui = MainWindow::new()?;
    let cfg = Rc::new(RefCell::new(config::load()));
    // Validate on load, fall back as a pair: missing/invalid/below-minimum /
    // implausibly huge legacy values resolve to the last validated geometry
    // (here: preferred 860x600), never clamped into a minimum-size window.
    // Otherwise-valid dimensions are clamped to the target monitor's usable
    // work area for display only; the stored last-known-good stays unclamped.
    let raw_window_size = cfg.borrow().window_size;
    let validated_window_size = common::resolve_window_size(raw_window_size);
    let raw_was_valid = raw_window_size
        .is_some_and(|[w, h]| common::is_valid_window_size_u32(w, h));
    {
        let [w, h] = validated_window_size;
        #[cfg(windows)]
        let (fw, fh) = platform::clamp_to_work_area_for_window(&ui, w as f32, h as f32);
        #[cfg(not(windows))]
        let (fw, fh) = (w as f32, h as f32);
        // Repair the in-memory geometry when the persisted value was corrupt
        // so later saves don't re-poison the file; the validated replacement
        // is written after successful normal presentation (see below). Keep
        // the unclamped validated pair: a clamped display size must never
        // overwrite a still-valid stored size.
        if !raw_was_valid {
            cfg.borrow_mut().window_size = Some(validated_window_size);
        }
        ui.window().set_size(slint::LogicalSize::new(fw, fh));
    }
    // In-memory last-known-good, held separately from live bounds.
    let tracker = Rc::new(RefCell::new(GeometryTracker::new(Some(
        validated_window_size,
    ))));
    // Shared with the tray re-show path: repair uses it but never overwrites
    // a real value with the preferred substitute.
    let shared_lkg: Rc<RefCell<Option<[u32; 2]>>> =
        Rc::new(RefCell::new(Some(validated_window_size)));
    lang::set(cfg.borrow().language.unwrap_or_else(Language::system));

    apply_config_to_ui(&ui, &cfg.borrow());
    ui.set_version(env!("CARGO_PKG_VERSION").into());
    // Put back TCP settings a crashed run may have left behind.
    let _ = erwin::restore();
    ui.set_congestion(provider_label(erwin::current_provider()).into());

    #[cfg(windows)]
    let tray = platform::setup(&ui, shared_lkg.clone());
    #[cfg(windows)]
    platform::watch_show_requests(&ui, &instance_guard, shared_lkg.clone());
    #[cfg(windows)]
    let has_tray = tray.is_some();
    #[cfg(not(windows))]
    let has_tray = false;

    // --- Window chrome ---
    {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        let tracker = tracker.clone();
        let shared_lkg = shared_lkg.clone();
        ui.on_close_window(move || {
            if let Some(ui) = w.upgrade() {
                // Normal close/hide: flush settled geometry, bypassing the
                // quiet wait but keeping every reject and transition gate.
                if capture_live_geometry(&ui, &mut cfg.borrow_mut(), &mut tracker.borrow_mut(), true) {
                    *shared_lkg.borrow_mut() = tracker.borrow().last_known_good;
                }
            }
            // Hide to tray instead of quitting; the tray's Thoát exits. Without
            // a tray there is no way back to a hidden window, so quit.
            if !has_tray {
                let _ = slint::quit_event_loop();
            } else if let Some(ui) = w.upgrade() {
                let _ = ui.window().hide();
            }
        });
    }
    {
        let w = ui.as_weak();
        ui.on_drag_window(move || {
            use slint::winit_030::WinitWindowAccessor;
            if let Some(ui) = w.upgrade() {
                ui.window().with_winit_window(|win| win.drag_window());
            }
        });
    }
    {
        let w = ui.as_weak();
        ui.on_resize_window(move |edge| {
            use slint::winit_030::winit::window::ResizeDirection as D;
            use slint::winit_030::WinitWindowAccessor;
            let direction = match edge {
                0 => D::North,
                1 => D::South,
                2 => D::West,
                3 => D::East,
                4 => D::NorthWest,
                5 => D::NorthEast,
                6 => D::SouthWest,
                _ => D::SouthEast,
            };
            if let Some(ui) = w.upgrade() {
                ui.window().with_winit_window(|win| win.drag_resize_window(direction));
            }
        });
    }
    {
        let w = ui.as_weak();
        ui.on_minimize_window(move || {
            if let Some(ui) = w.upgrade() {
                ui.window().set_minimized(true);
            }
        });
    }

    // --- Engine toggle ---
    {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        ui.on_toggle_engine(move |active| {
            let Some(ui) = w.upgrade() else { return };
            if active {
                // The engine needs real IPs, so DoH comes first: turn it on if
                // the user had it off, and start the engine once it is applied.
                if !cfg.borrow().doh_enabled {
                    cfg.borrow_mut().doh_enabled = true;
                    config::save(&cfg.borrow());
                    ui.set_doh_enabled(true);
                }
                ui.set_engine_active(true);
                ui.set_engine_status(tr("Đang bật DoH…", "Starting DoH…").into());
                let snapshot = cfg.borrow().clone();
                if hange::is_enabled() {
                    start_engine(&ui, &snapshot);
                } else {
                    let (choice, http3) = (dns_choice(&snapshot), snapshot.doh_http3);
                    enable_doh_then(&ui, w.clone(), choice, http3, move |ui, _, ok| {
                        // Switched off again while DoH was coming up.
                        if !ui.get_engine_active() {
                            return;
                        }
                        if ok {
                            start_engine(ui, &snapshot);
                        } else {
                            ui.set_engine_active(false);
                            ui.set_engine_status(tr("Lỗi", "Error").into());
                            ui.set_log(t!("{} Engine chưa bật vì cần DoH.", "{} The engine needs DoH, so it stayed off.", ui.get_log()).into());
                        }
                    });
                }
            } else {
                // DoH stays as the user set it: it works on its own.
                engine::stop();
                ui.set_engine_active(false);
                ui.set_engine_status(tr("Đang tắt", "Off").into());
                ui.set_log(tr("Đã tắt engine. DNS mã hóa vẫn giữ nguyên.", "Engine off. Encrypted DNS stays on.").into());
            }
        });
    }

    // --- Scope ---
    {
        let cfg = cfg.clone();
        let w = ui.as_weak();
        ui.on_set_scope(move |i| {
            cfg.borrow_mut().scope = scope_from_index(i);
            config::save(&cfg.borrow());
            if let Some(ui) = w.upgrade() {
                ui.set_scope(i);
                restart_engine_if_active(&ui, &cfg.borrow());
            }
        });
    }
    {
        let cfg = cfg.clone();
        let w = ui.as_weak();
        ui.on_set_transport_profile(move |i| {
            let profile = TransportProfile::ALL.get(i as usize).copied().unwrap_or_default();
            cfg.borrow_mut().transport_profile = profile;
            config::save(&cfg.borrow());
            if let Some(ui) = w.upgrade() {
                ui.set_transport_profile(transport_profile_index(profile));
                restart_engine_if_active(&ui, &cfg.borrow());
            }
        });
    }
    // --- Compatibility Mode ---
    {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        ui.on_set_game_protection(move |on| {
            let Some(ui) = w.upgrade() else { return };
            cfg.borrow_mut().compatibility_mode_enabled = on;
            config::save(&cfg.borrow());
            ui.set_game_protection(on);
            apply_lists(&cfg.borrow());
        });
    }
    // --- Domain list sheet (Custom exclusions / Selected hosts) ---
    // Edits change `cfg`, the UI and the running engine at once (hot reload,
    // open connections are kept); the file is written 500 ms after the last
    // edit, and right away when the sheet closes.
    let domain_save = Rc::new(slint::Timer::default());
    let domains_changed = Rc::new(Cell::new(false));
    let schedule_domain_save = {
        let timer = domain_save.clone();
        let cfg = cfg.clone();
        let changed = domains_changed.clone();
        move || {
            changed.set(true);
            let cfg = cfg.clone();
            timer.start(slint::TimerMode::SingleShot, DOMAIN_SAVE_DEBOUNCE, move || config::save(&cfg.borrow()));
        }
    };
    {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        let schedule = schedule_domain_save.clone();
        ui.on_domain_add(move |sheet, text| {
            let Some(ui) = w.upgrade() else { return };
            let Some(domain) = common::domain::normalize_domain(&text) else {
                ui.set_domain_highlight("".into());
                ui.set_domain_error(if text.trim().is_empty() {
                    tr("Nhập một tên miền, ví dụ example.com.", "Type a domain, for example example.com.").into()
                } else {
                    t!("\"{}\" không phải tên miền hợp lệ.", "\"{}\" is not a valid domain.", text.trim()).into()
                });
                return;
            };
            ui.set_domain_highlight(domain.as_str().into());
            {
                let mut cfg = cfg.borrow_mut();
                let list = domain_list(&mut cfg, sheet);
                if list.contains(&domain) {
                    ui.set_domain_error(t!("{domain} đã có trong danh sách.", "{domain} is already in the list.").into());
                    return;
                }
                list.push(domain.clone());
            }
            ui.set_domain_error("".into());
            set_domain_lists(&ui, &cfg.borrow());
            apply_lists(&cfg.borrow());
            schedule();
        });
    }
    {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        let schedule = schedule_domain_save.clone();
        ui.on_domain_remove(move |sheet, domain| {
            let Some(ui) = w.upgrade() else { return };
            {
                let mut cfg = cfg.borrow_mut();
                let list = domain_list(&mut cfg, sheet);
                let before = list.len();
                list.retain(|d| d != domain.as_str());
                if list.len() == before {
                    return;
                }
            }
            ui.set_domain_error("".into());
            ui.set_domain_highlight("".into());
            set_domain_lists(&ui, &cfg.borrow());
            apply_lists(&cfg.borrow());
            schedule();
        });
    }
    {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        let changed = domains_changed.clone();
        let timer = domain_save.clone();
        ui.on_domain_import(move |kind| {
            let Some(ui) = w.upgrade() else { return };
            let added = common::domain::merge_domains(&mut cfg.borrow_mut().selected_hosts, &suggested_domains(&kind));
            // Imports are saved at once (no debounce).
            timer.stop();
            config::save(&cfg.borrow());
            apply_lists(&cfg.borrow());
            changed.set(true);
            ui.set_domain_highlight("".into());
            ui.set_domain_error("".into());
            set_domain_lists(&ui, &cfg.borrow());
            ui.set_log(t!("Đã nhập {added} tên miền.", "Imported {added} domains.").into());
        });
    }
    {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        let changed = domains_changed.clone();
        let timer = domain_save.clone();
        ui.on_domain_sheet_closed(move || {
            let Some(ui) = w.upgrade() else { return };
            ui.set_domain_error("".into());
            ui.set_domain_highlight("".into());
            if changed.replace(false) {
                timer.stop();
                config::save(&cfg.borrow());
            }
        });
    }

    // --- TCP congestion ---
    {
        let cfg = cfg.clone();
        ui.on_set_congestion(move |i| {
            cfg.borrow_mut().congestion = congestion_from_index(i);
            config::save(&cfg.borrow());
        });
    }
    {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        ui.on_apply_congestion(move || {
            if let Some(ui) = w.upgrade() {
                set_tcp_enabled(&ui, &cfg, true);
                apply_congestion(&ui, w.clone(), cfg.borrow().congestion);
            }
        });
    }
    {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        ui.on_set_tcp_enabled(move |on| {
            let Some(ui) = w.upgrade() else { return };
            set_tcp_enabled(&ui, &cfg, on);
            if on {
                apply_congestion(&ui, w.clone(), cfg.borrow().congestion);
            } else {
                ui.set_log(tr("Đang trả TCP về như trước khi bật…", "Putting TCP back as it was…").into());
                restore_tcp(w.clone(), tr("Đã tắt tối ưu TCP, Windows dùng lại thiết lập cũ.", "TCP tuning off, Windows uses its previous settings."));
            }
        });
    }
    // The ISP found while Yeager was off (see "ISP" below).
    let isp_before: Arc<Mutex<String>> = Arc::default();
    {
        let w = ui.as_weak();
        let isp_before = isp_before.clone();
        ui.on_run_diagnose(move || {
            let Some(ui) = w.upgrade() else { return };
            ui.set_diag_running(true);
            ui.set_diag_pick(-1);
            let progress = w.clone();
            let isp_before = isp_before.clone();
            spawn(
                w.clone(),
                move || {
                    erwin::diagnose(|msg| {
                        let w = progress.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = w.upgrade() {
                                ui.set_diag_status(msg.into());
                            }
                        });
                    })
                },
                move |ui, res| {
                    ui.set_diag_running(false);
                    match res {
                        Ok(report) => {
                            if let Some(found) = &report.isp {
                                note_isp(&ui, &isp_before, found);
                            }
                            ui.set_diag_pick(congestion_index(report.best.choice));
                            ui.set_diag_pick_label(report.best.choice.label().into());
                            ui.set_diag_status(capitalize(&report.best.reason).into());
                            ui.set_log(t!("Chẩn đoán xong: đề xuất {}.", "Diagnosis done: {} suggested.", report.best.choice.label()).into());
                        }
                        Err(e) => ui.set_diag_status(t!("Lỗi: {e}", "Error: {e}").into()),
                    }
                },
            );
        });
    }
    {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        ui.on_apply_recommendation(move || {
            let Some(ui) = w.upgrade() else { return };
            let i = ui.get_diag_pick();
            if i < 0 {
                return;
            }
            cfg.borrow_mut().congestion = congestion_from_index(i);
            ui.set_congestion_sel(i);
            set_tcp_enabled(&ui, &cfg, true);
            apply_congestion(&ui, w.clone(), cfg.borrow().congestion);
        });
    }
    {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        ui.on_set_low_latency(move |on| {
            let Some(ui) = w.upgrade() else { return };
            cfg.borrow_mut().low_latency = on;
            config::save(&cfg.borrow());
            ui.set_low_latency(on);
            ui.set_latency_busy(true);
            if on {
                ui.set_log(tr("Đang bật độ trễ thấp, mạng sẽ ngắt vài giây…", "Turning low latency on, the network drops for a few seconds…").into());
                spawn(w.clone(), erwin::latency::apply, move |ui, res| {
                    ui.set_latency_busy(false);
                    match res {
                        Ok(applied) => ui.set_log(if applied.not_restarted.is_empty() {
                            t!(
                                "Đã bật độ trễ thấp trên {}. Khởi động lại máy để bỏ giới hạn mạng khi phát media.",
                                "Low latency is on for {}. Restart Windows to lift media network throttling.",
                                applied.adapters.join(", ")
                            )
                        } else {
                            t!(
                                "Đã bật độ trễ thấp trên {}; {} cần khởi động lại máy để có hiệu lực.",
                                "Low latency is on for {}; {} needs a Windows restart to take effect.",
                                applied.adapters.join(", "),
                                applied.not_restarted.join(", ")
                            )
                        }
                        .into()),
                        Err(e) => {
                            // Switch off, which also puts back anything half-applied.
                            ui.invoke_set_low_latency(false);
                            ui.set_log(t!("Không bật được độ trễ thấp: {e}", "Could not turn low latency on: {e}").into());
                        }
                    }
                });
            } else {
                ui.set_log(tr("Đang trả thiết lập mạng về như cũ…", "Putting the network settings back…").into());
                spawn(w.clone(), erwin::latency::restore, |ui, res| {
                    ui.set_latency_busy(false);
                    ui.set_log(match res {
                        Ok(_) => tr("Đã tắt độ trễ thấp, Windows dùng lại thiết lập cũ.", "Low latency off, Windows uses its previous settings.").into(),
                        Err(e) => t!("Không khôi phục hết được: {e}", "Could not restore everything: {e}").into(),
                    });
                });
            }
        });
    }
    {
        let w = ui.as_weak();
        ui.on_run_latency_check(move || {
            let Some(ui) = w.upgrade() else { return };
            ui.set_latency_busy(true);
            ui.set_latency_status(tr("Đang ping trong khoảng 10 giây…", "Pinging for about 10 seconds…").into());
            spawn(w.clone(), erwin::latency::check, |ui, res| {
                ui.set_latency_busy(false);
                ui.set_latency_status(match res {
                    Ok((_, verdict)) => verdict.into(),
                    Err(e) => t!("Lỗi: {e}", "Error: {e}").into(),
                });
            });
        });
    }
    ui.on_open_repo(|site| {
        let url = if site == 1 { GITLAB_URL } else { REPO_URL };
        // Handed to the shell so the browser does not inherit admin rights.
        let _ = common::process::hidden("explorer").arg(url).spawn();
    });
    // The network card: addresses looked up on demand and every few minutes
    // while the window shows.
    let network_at: Rc<Cell<Option<Instant>>> = Rc::default();
    {
        let w = ui.as_weak();
        let network_at = network_at.clone();
        ui.on_refresh_network(move || {
            if let Some(ui) = w.upgrade() {
                network_at.set(Some(Instant::now()));
                refresh_network(&ui);
            }
        });
    }
    // DNS latency, shown on the home and DNS pages while the window shows.
    let dns_stats = Arc::new(Mutex::new(DnsStats::default()));
    let dns_stats_timer = slint::Timer::default();
    {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        dns_stats_timer.start(slint::TimerMode::Repeated, Duration::from_secs(2), move || {
            if let Some(ui) = w.upgrade().filter(|ui| ui.window().is_visible()) {
                refresh_dns_stats(&ui, &cfg.borrow(), &dns_stats);
                refresh_engine_stats(&ui);
                if ui.get_page() == 0 && network_at.get().is_none_or(|at| at.elapsed() >= NETWORK_REFRESH) {
                    network_at.set(Some(Instant::now()));
                    refresh_network(&ui);
                }
            }
        });
    }
    {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        ui.on_reset_tcp(move || {
            let Some(ui) = w.upgrade() else { return };
            set_tcp_enabled(&ui, &cfg, false);
            // Low latency is part of what Yeager changed, so it goes back too.
            let latency = ui.get_low_latency() || erwin::latency::is_active();
            if latency {
                cfg.borrow_mut().low_latency = false;
                config::save(&cfg.borrow());
                ui.set_low_latency(false);
                ui.set_latency_busy(true);
            }
            ui.set_log(if latency {
                tr("Đang khôi phục mặc định Windows, mạng sẽ ngắt vài giây…", "Restoring Windows defaults, the network drops for a few seconds…")
            } else {
                tr("Đang khôi phục mặc định Windows…", "Restoring Windows defaults…")
            }
            .into());
            spawn(
                w.clone(),
                move || {
                    let tcp = erwin::reset_defaults().map(|_| provider_label(erwin::current_provider()));
                    let latency = if latency { erwin::latency::restore().map(|_| ()) } else { Ok(()) };
                    (tcp, latency)
                },
                move |ui, (tcp, low)| {
                    if latency {
                        ui.set_latency_busy(false);
                    }
                    match (tcp, low) {
                        (Ok(p), Ok(())) => {
                            ui.set_log(if latency {
                                t!(
                                    "Đã khôi phục mặc định Windows ({}) và tắt độ trễ thấp.",
                                    "Windows defaults restored ({}) and low latency off.",
                                    p.to_uppercase()
                                )
                            } else {
                                t!("Đã khôi phục mặc định Windows ({}).", "Windows defaults restored ({}).", p.to_uppercase())
                            }
                            .into());
                            ui.set_congestion(p.into());
                        }
                        (Ok(p), Err(e)) => {
                            ui.set_congestion(p.into());
                            ui.set_log(t!("Không khôi phục hết được: {e}", "Could not restore everything: {e}").into());
                        }
                        (Err(e), _) => ui.set_log(t!("Lỗi: {e}", "Error: {e}").into()),
                    }
                },
            );
        });
    }

    // --- DNS ---
    {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        ui.on_set_doh(move |on| {
            cfg.borrow_mut().doh_enabled = on;
            config::save(&cfg.borrow());
            let Some(ui) = w.upgrade() else { return };
            if on {
                enable_doh(&ui, w.clone(), dns_choice(&cfg.borrow()), cfg.borrow().doh_http3);
            } else if ui.get_engine_active() {
                // The engine cannot run without DoH, so it goes too.
                engine::stop();
                ui.set_engine_active(false);
                ui.set_engine_status(tr("Đang tắt", "Off").into());
                restore_doh(&ui, w.clone(), tr("Đã tắt DNS mã hóa và engine (engine cần DoH).", "Encrypted DNS and the engine are off (the engine needs DoH)."));
            } else {
                restore_doh(&ui, w.clone(), tr("Đã tắt DNS mã hóa.", "Encrypted DNS off."));
            }
        });
    }
    {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        ui.on_set_doh_provider(move |i| {
            {
                let mut cfg = cfg.borrow_mut();
                cfg.doh_auto = i < 0;
                if let Some(&p) = usize::try_from(i).ok().and_then(|i| DohProvider::ALL.get(i)) {
                    cfg.doh_provider = p;
                }
                config::save(&cfg);
            }
            if let Some(ui) = w.upgrade() {
                ui.set_doh_provider(provider_index(&cfg.borrow()));
                if cfg.borrow().doh_enabled {
                    enable_doh(&ui, w.clone(), dns_choice(&cfg.borrow()), cfg.borrow().doh_http3);
                }
            }
        });
    }
    {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        ui.on_set_doh_http3(move |on| {
            cfg.borrow_mut().doh_http3 = on;
            config::save(&cfg.borrow());
            let Some(ui) = w.upgrade() else { return };
            ui.set_doh_http3(on);
            if hange::is_enabled() {
                enable_doh(&ui, w.clone(), dns_choice(&cfg.borrow()), on);
            }
        });
    }
    {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        ui.on_test_dns(move || {
            let Some(ui) = w.upgrade() else { return };
            let provider = hange::system_provider(dns_choice(&cfg.borrow()));
            ui.set_log(tr("Đang kiểm tra DNS mã hóa…", "Checking encrypted DNS…").into());
            spawn(
                w.clone(),
                // Reaching the resolver from the app proves little on its own;
                // when DNS is on, also check that Windows itself goes through it.
                move || {
                    let (ip, transport) = hange::resolve(provider, "discord.com")?;
                    let ifaces = if hange::is_enabled() { hange::verify_system(provider)? } else { Vec::new() };
                    // Without the stub the test went straight out, but Windows
                    // resolves through its own DoH: report what Windows uses.
                    let transport = if hange::is_enabled() && !hange::stub_running() { None } else { transport };
                    Ok::<_, common::Error>((ip, transport, ifaces))
                },
                move |ui, res| match res {
                    Ok((ip, transport, ifaces)) => {
                        let via = transport.map_or("DoH Windows", hange::Transport::label);
                        let provider = hange::status().map_or(provider, |s| s.provider);
                        ui.set_dns_status(format!("OK · {} · {via} · discord.com → {ip}", provider.label()).into());
                        ui.set_log(if ifaces.is_empty() {
                            t!("Máy chủ {} phản hồi tốt qua {via}.", "{} answers fine over {via}.", provider.label())
                        } else {
                            t!(
                                "Windows đang dùng DNS mã hóa {} ({via}) trên {}.",
                                "Windows uses encrypted DNS {} ({via}) on {}.",
                                provider.label(),
                                ifaces.join(", ")
                            )
                        }.into());
                    }
                    Err(e) => {
                        ui.set_dns_status(tr("Thất bại", "Failed").into());
                        ui.set_log(t!("DoH lỗi: {e}", "DoH error: {e}").into());
                    }
                },
            );
        });
    }

    // --- Launch options ---
    {
        let cfg = cfg.clone();
        ui.on_set_connect_on_launch(move |on| {
            cfg.borrow_mut().connect_on_launch = on;
            config::save(&cfg.borrow());
        });
    }
    {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        ui.on_set_launch_login(move |on| {
            cfg.borrow_mut().launch_at_login = on;
            config::save(&cfg.borrow());
            let exe = std::env::current_exe().unwrap_or_default();
            let Some(ui) = w.upgrade() else { return };
            match erwin::set_launch_at_login(on, &exe) {
                Ok(()) => ui.set_log(if on {
                    tr("Đã bật khởi động cùng Windows.", "Start with Windows is on.")
                } else {
                    tr("Đã tắt khởi động cùng Windows.", "Start with Windows is off.")
                }
                .into()),
                Err(e) => ui.set_log(format!("{e}").into()),
            }
        });
    }

    // --- Appearance ---
    {
        let cfg = cfg.clone();
        ui.on_set_dark(move |on| {
            cfg.borrow_mut().dark = on;
            config::save(&cfg.borrow());
        });
    }
    {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        ui.on_set_accent(move |c| {
            cfg.borrow_mut().accent = format!("#{:02x}{:02x}{:02x}", c.red(), c.green(), c.blue());
            config::save(&cfg.borrow());
            if let Some(ui) = w.upgrade() {
                ui.global::<Theme>().set_accent(c);
            }
        });
    }

    // --- Language ---
    {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        ui.on_set_language(move |english| {
            let language = if english { Language::En } else { Language::Vi };
            lang::set(language);
            cfg.borrow_mut().language = Some(language);
            config::save(&cfg.borrow());
            if let Some(ui) = w.upgrade() {
                refresh_texts(&ui, &cfg.borrow());
            }
        });
    }

    // --- ISP ---
    // Looked up once at start, then again only by Diagnose. The value from
    // before Yeager was turned on comes back when it is turned off, so
    // toggling never costs a request.
    {
        let w = ui.as_weak();
        let isp_before = isp_before.clone();
        slint::Timer::single_shot(Duration::from_secs(5), move || {
            // The network may still be coming up at sign-in, so try a few times.
            let lookup = || {
                let mut tries = 0;
                loop {
                    match erwin::probe::isp() {
                        Err(_) if tries < 2 => {
                            tries += 1;
                            std::thread::sleep(Duration::from_secs(20));
                        }
                        res => return res,
                    }
                }
            };
            spawn(w, lookup, move |ui, res| {
                match res {
                    Ok(found) => note_isp(&ui, &isp_before, &found),
                    Err(e) => ui.set_log(e.to_string().into()),
                }
            });
        });
    }
    {
        let w = ui.as_weak();
        let isp_before = isp_before.clone();
        let was_active = Rc::new(std::cell::Cell::new(false));
        let timer = Box::leak(Box::new(slint::Timer::default()));
        timer.start(slint::TimerMode::Repeated, Duration::from_millis(250), move || {
            let Some(ui) = w.upgrade() else { return };
            let active = ui.get_engine_active();
            let before = isp_before.lock().unwrap().clone();
            if was_active.replace(active) && !active && !before.is_empty() {
                ui.set_isp(before.into());
            }
        });
    }

    // --- Updates ---
    // Set once a new exe is in place: Yeager quits, puts Windows back, then
    // starts it (with the engine back on if it was on).
    let restart: Arc<Mutex<Option<(PathBuf, bool)>>> = Arc::default();
    ui.set_update_status(t!("Phiên bản hiện tại {}", "Current version {}", updater::current()).into());
    {
        let w = ui.as_weak();
        ui.on_check_update(move || {
            if let Some(ui) = w.upgrade() {
                check_for_update(&ui, w.clone(), false);
            }
        });
    }
    {
        let w = ui.as_weak();
        let restart = restart.clone();
        ui.on_install_update(move || {
            let Some(ui) = w.upgrade() else { return };
            let version = ui.get_update_version().to_string();
            if version.is_empty() {
                return;
            }
            ui.set_update_dialog(2);
            ui.set_update_busy(true);
            ui.set_log(t!("Đang tải Yeager {version}…", "Downloading Yeager {version}…").into());
            let restart = restart.clone();
            spawn(w.clone(), move || updater::download_and_install(&version), move |ui, res| {
                ui.set_update_busy(false);
                match res {
                    Ok(path) => {
                        *restart.lock().unwrap() = Some((path, ui.get_engine_active()));
                        ui.set_log(tr("Đã tải xong, đang khởi động lại…", "Downloaded, restarting…").into());
                        let _ = slint::quit_event_loop();
                    }
                    Err(failure) => {
                        ui.set_update_error(failure.message().into());
                        ui.set_update_dialog(3);
                        ui.set_log(tr("Chưa cập nhật được.", "The update did not finish.").into());
                    }
                }
            });
        });
    }
    {
        let w = ui.as_weak();
        ui.on_open_release_notes(move || {
            if let Some(ui) = w.upgrade() {
                updater::open_url(&updater::notes_url(&ui.get_update_version()));
            }
        });
    }
    ui.on_open_download_page(|| updater::open_url(updater::releases_page()));
    {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        ui.on_set_check_updates(move |on| {
            cfg.borrow_mut().check_updates = on;
            config::save(&cfg.borrow());
            if let Some(ui) = w.upgrade() {
                ui.set_check_updates(on);
            }
        });
    }
    // Check quietly a little after start, once DNS has settled, then every
    // few hours. A new version only shows in the sidebar, the tray and
    // General; nothing is installed without asking.
    let quiet_check = {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        move || {
            if let Some(ui) = w.upgrade()
                && cfg.borrow().check_updates {
                check_for_update(&ui, w.clone(), true);
            }
        }
    };
    slint::Timer::single_shot(Duration::from_secs(10), quiet_check.clone());
    let update_timer = slint::Timer::default();
    update_timer.start(slint::TimerMode::Repeated, UPDATE_CHECK_INTERVAL, quiet_check);

    // Auto-connect on launch (which brings DoH up first), or DoH alone if
    // that is all the user keeps on. Otherwise undo DNS settings a crashed
    // run may have left pointing at a stub that is no longer there.
    let (connect, doh) = (cfg.borrow().connect_on_launch, cfg.borrow().doh_enabled);
    if connect || resume {
        ui.invoke_toggle_engine(true);
    } else if doh {
        enable_doh(&ui, ui.as_weak(), dns_choice(&cfg.borrow()), cfg.borrow().doh_http3);
    } else {
        std::thread::spawn(hange::clean_up_leftovers);
    }
    // TCP tuning stands on its own: it follows its own switch, not the engine.
    if cfg.borrow().tcp_enabled {
        apply_congestion(&ui, ui.as_weak(), cfg.borrow().congestion);
    }
    // Low-latency settings outlive the app; only put them back if the switch
    // is off but some are still in place (e.g. a config reset).
    if !cfg.borrow().low_latency && erwin::latency::is_active() {
        std::thread::spawn(erwin::latency::restore);
    }

    ui.show()?;
    #[cfg(windows)]
    platform::apply_window_chrome(&ui);
    // Commit the validated pair only after native bounds have settled. A
    // still-valid loaded size is left in place when the live size is only a
    // transient or work-area-constrained snapshot. This also latches
    // `initialized` from real presentation instead of hardcoding true.
    {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        let tracker = tracker.clone();
        let shared_lkg = shared_lkg.clone();
        slint::Timer::single_shot(GEOMETRY_SETTLE, move || {
            let Some(ui) = w.upgrade() else { return };
            let scale = ui.window().scale_factor();
            let size = ui.window().size().to_logical(scale);
            let work_area = current_work_area(&ui);
            let mut tr = tracker.borrow_mut();
            // Baseline for later DPI / work-area transition detection.
            tr.last_scale = Some(scale);
            tr.last_work_area = work_area;
            // Latch initialization only on coherent settled normal geometry.
            let coherent = should_accept_geometry(
                ui.window().is_visible(),
                ui.window().is_minimized(),
                ui.window().is_maximized(),
                true,
                scale,
                size.width,
                size.height,
            ) && !is_work_area_constrained_snapshot(
                [size.width.round() as u32, size.height.round() as u32],
                tr.last_known_good,
                work_area,
            );
            if coherent {
                tr.initialized = true;
                *shared_lkg.borrow_mut() = tr.last_known_good;
                // If the file held corrupt geometry, persist the validated
                // replacement now that presentation succeeded. A valid loaded
                // size is never replaced by a transient live snapshot here.
                if !raw_was_valid {
                    let mut c = cfg.borrow_mut();
                    if c.window_size != tr.last_known_good {
                        c.window_size = tr.last_known_good;
                    }
                    config::save(&c);
                }
            } else {
                // Not coherent yet: retry once after another settle interval
                // rather than marking initialized on a mid-transition sample.
                let w2 = w.clone();
                let cfg2 = cfg.clone();
                let tracker2 = tracker.clone();
                let shared2 = shared_lkg.clone();
                slint::Timer::single_shot(GEOMETRY_SETTLE, move || {
                    let Some(ui) = w2.upgrade() else { return };
                    let scale = ui.window().scale_factor();
                    let size = ui.window().size().to_logical(scale);
                    let work_area = current_work_area(&ui);
                    let mut tr = tracker2.borrow_mut();
                    tr.last_scale = Some(scale);
                    tr.last_work_area = work_area;
                    if should_accept_geometry(
                        ui.window().is_visible(),
                        ui.window().is_minimized(),
                        ui.window().is_maximized(),
                        true,
                        scale,
                        size.width,
                        size.height,
                    ) {
                        tr.initialized = true;
                        *shared2.borrow_mut() = tr.last_known_good;
                        if !raw_was_valid {
                            let mut c = cfg2.borrow_mut();
                            if c.window_size != tr.last_known_good {
                                c.window_size = tr.last_known_good;
                            }
                            config::save(&c);
                        }
                    }
                });
            }
        });
    }
    // Capture settled normal geometry on resize/move with a debounce that
    // fires after the geometry has been quiet, plus flushes at close/exit.
    // DPI / work-area transitions are skipped until size and scale cohere.
    let geometry_timer = slint::Timer::default();
    {
        let w = ui.as_weak();
        let cfg = cfg.clone();
        let tracker = tracker.clone();
        let shared_lkg = shared_lkg.clone();
        geometry_timer.start(slint::TimerMode::Repeated, GEOMETRY_POLL, move || {
            if let Some(ui) = w.upgrade() {
                if capture_live_geometry(
                    &ui,
                    &mut cfg.borrow_mut(),
                    &mut tracker.borrow_mut(),
                    false,
                ) {
                    *shared_lkg.borrow_mut() = tracker.borrow().last_known_good;
                }
            }
        });
    }

    // `ui.run()` would end as soon as the window hides to the tray, taking the
    // tray with it. Run until the tray's Thoát (or close without a tray) quits.
    slint::run_event_loop_until_quit()?;
    // A domain edit still waiting for its debounced save.
    if domain_save.running() {
        domain_save.stop();
        config::save(&cfg.borrow());
    }
    {
        let mut tr = tracker.borrow_mut();
        let mut c = cfg.borrow_mut();
        if capture_live_geometry(&ui, &mut c, &mut tr, true) {
            *shared_lkg.borrow_mut() = tr.last_known_good;
        }
    }
    drop(geometry_timer);
    let _ = ui.hide();
    #[cfg(windows)]
    drop(tray);

    engine::stop();
    let _ = erwin::restore();
    hange::disable();
    drop(update_timer);
    let restart = restart.lock().unwrap().take();
    if let Some((path, connect)) = restart {
        updater::restart(&path, connect);
    }
    Ok(())
}

/// Looks up the local and public addresses for the network card off the UI
/// thread.
fn refresh_network(ui: &MainWindow) {
    if ui.get_net_busy() {
        return;
    }
    ui.set_net_busy(true);
    let lookup = || {
        // Without a local route over a family there is nothing to ask
        // Cloudflare, and on IPv4-only networks the attempt could stall.
        let lookup = |ipv6: bool| {
            let local = erwin::probe::local_ip(ipv6);
            (local, local.and_then(|_| erwin::probe::public_ip(ipv6).ok()))
        };
        let v6 = std::thread::spawn(move || lookup(true));
        let v4 = lookup(false);
        (v4, v6.join().unwrap_or_default())
    };
    spawn(ui.as_weak(), lookup, |ui, ((local4, public4), (local6, public6))| {
        let show = |ip: Option<std::net::IpAddr>, none: &str| ip.map_or_else(|| none.to_string(), |ip| ip.to_string());
        let none = tr("Không có", "None");
        ui.set_net_local4(show(local4, none).into());
        ui.set_net_public4(show(public4, if local4.is_some() { tr("Không lấy được", "Unavailable") } else { none }).into());
        ui.set_net_local6(show(local6, tr("Không có (chỉ IPv4)", "None (IPv4 only)")).into());
        ui.set_net_public6(show(public6, if local6.is_some() { tr("Không lấy được", "Unavailable") } else { tr("Mạng chỉ có IPv4", "IPv4-only network") }).into());
        ui.set_net_busy(false);
    });
}

/// Whether a live window snapshot may become the persisted normal geometry.
///
/// Accepts only settled normal geometry: visible, non-minimized,
/// non-maximized, initialization complete, finite positive dimensions with a
/// valid positive scale. Transient zero/below-minimum sizes are ignored so
/// they never overwrite last-known-good. A deliberate stable 700x500 is
/// accepted; minimum size alone is not corruption.
pub fn should_accept_geometry(
    visible: bool,
    minimized: bool,
    maximized: bool,
    initialized: bool,
    scale: f32,
    w: f32,
    h: f32,
) -> bool {
    if !visible || minimized || maximized || !initialized {
        return false;
    }
    if !scale.is_finite() || scale <= 0.0 {
        return false;
    }
    common::is_valid_window_size(w, h)
}

/// Validated startup size for a persisted value: falls back as a pair to the
/// preferred 860x600, never clamping garbage into a minimum-size window.
pub fn startup_window_size(raw: Option<[u32; 2]>) -> (f32, f32) {
    let [w, h] = common::resolve_window_size(raw);
    (w as f32, h as f32)
}

/// Minimal store step exercised by regression tests: updates `stored` only
/// for settled normal geometry, leaving a stored last-known-good unchanged
/// for minimized, maximized, hidden, uninitialized, bad-scale and transient
/// rejects. Returns true when the stored value changed.
pub fn try_update_geometry(
    stored: &mut Option<[u32; 2]>,
    visible: bool,
    minimized: bool,
    maximized: bool,
    initialized: bool,
    scale: f32,
    w: f32,
    h: f32,
) -> bool {
    if !should_accept_geometry(visible, minimized, maximized, initialized, scale, w, h) {
        return false;
    }
    let next = Some([w.round() as u32, h.round() as u32]);
    if *stored == next {
        return false;
    }
    *stored = next;
    true
}

/// Settled capture core: debounced, transition-aware, work-area-aware.
///
/// - Rejects hidden/minimized/maximized/uninitialized/bad-scale/
///
/// below-minimum samples without touching `stored` or `tracker`.
/// - Skips saves across a DPI or work-area transition until size and scale
///   are coherent (updates baselines, clears pending, returns false).
/// - Holds last-known-good separately: a work-area-constrained snapshot of a
///   still-valid stored size never overwrites it.
/// - Polls (`force=false`) commit only after the candidate has been quiet for
///   [`GEOMETRY_QUIET`]; close/exit (`force=true`) commits a coherent valid
///   candidate at once.
///
/// Returns true when `stored`/`tracker.last_known_good` changed (caller
/// persists and syncs the shared re-show value).
#[allow(clippy::too_many_arguments)]
pub fn remember_window_size_sample(
    stored: &mut Option<[u32; 2]>,
    tracker: &mut GeometryTracker,
    visible: bool,
    minimized: bool,
    maximized: bool,
    scale: f32,
    w: f32,
    h: f32,
    work_area: Option<(f32, f32)>,
    now: Instant,
    force: bool,
) -> bool {
    if !tracker.initialized {
        return false;
    }
    if !should_accept_geometry(visible, minimized, maximized, true, scale, w, h) {
        tracker.pending = None;
        tracker.pending_since = None;
        return false;
    }
    // DPI / work-area transition: skip until size and scale cohere.
    let scale_changed =
        tracker.last_scale.is_some_and(|s| (s - scale).abs() > 0.01 || !s.is_finite());
    let area_changed = match (tracker.last_work_area, work_area) {
        (Some((a, b)), Some((c, d))) => (a - c).abs() > 1.0 || (b - d).abs() > 1.0,
        (None, Some(_)) | (Some(_), None) => tracker.last_scale.is_some(),
        (None, None) => false,
    };
    if scale_changed || area_changed {
        tracker.last_scale = Some(scale);
        tracker.last_work_area = work_area;
        tracker.pending = None;
        tracker.pending_since = None;
        return false;
    }
    // First coherent sample establishes baselines without skipping.
    if tracker.last_scale.is_none() {
        tracker.last_scale = Some(scale);
        tracker.last_work_area = work_area;
    }
    let candidate = [w.round() as u32, h.round() as u32];
    let candidate_opt = Some(candidate);
    if tracker.last_known_good == candidate_opt && *stored == candidate_opt {
        tracker.pending = None;
        tracker.pending_since = None;
        return false;
    }
    // Do not store a temporary constrained size over a still-valid good.
    if is_work_area_constrained_snapshot(candidate, tracker.last_known_good.or(*stored), work_area) {
        tracker.pending = None;
        tracker.pending_since = None;
        return false;
    }
    if is_work_area_constrained_snapshot(candidate, *stored, work_area) {
        tracker.pending = None;
        tracker.pending_since = None;
        return false;
    }
    if force {
        tracker.last_known_good = candidate_opt;
        tracker.pending = None;
        tracker.pending_since = None;
        if *stored == candidate_opt {
            return false;
        }
        *stored = candidate_opt;
        return true;
    }
    // Debounce: fire only after the geometry has been quiet.
    match tracker.pending {
        Some(p) if p == candidate => {
            if tracker.pending_since.is_some_and(|t| now.duration_since(t) >= GEOMETRY_QUIET) {
                tracker.last_known_good = candidate_opt;
                tracker.pending = None;
                tracker.pending_since = None;
                if *stored == candidate_opt {
                    return false;
                }
                *stored = candidate_opt;
                return true;
            }
            false
        }
        _ => {
            tracker.pending = candidate_opt;
            tracker.pending_since = Some(now);
            false
        }
    }
}

#[cfg(windows)]
fn current_work_area(ui: &MainWindow) -> Option<(f32, f32)> {
    platform::work_area_size_for_window(ui)
}

#[cfg(not(windows))]
fn current_work_area(_ui: &MainWindow) -> Option<(f32, f32)> {
    None
}

/// Reads live window state and runs the settled capture core. Saves on commit.
/// Returns true when the stored geometry changed.
fn capture_live_geometry(
    ui: &MainWindow,
    cfg: &mut Config,
    tracker: &mut GeometryTracker,
    force: bool,
) -> bool {
    let visible = ui.window().is_visible();
    let minimized = ui.window().is_minimized();
    let maximized = ui.window().is_maximized();
    let scale = ui.window().scale_factor();
    let size = ui.window().size().to_logical(scale);
    let work_area = current_work_area(ui);
    let now = Instant::now();
    if remember_window_size_sample(
        &mut cfg.window_size,
        tracker,
        visible,
        minimized,
        maximized,
        scale,
        size.width,
        size.height,
        work_area,
        now,
        force,
    ) {
        config::save(cfg);
        return true;
    }
    false
}

/// Shows the ISP a lookup found, and keeps it as the value to return to when
/// Yeager is turned off if it was found while Yeager was off.
fn note_isp(ui: &MainWindow, before: &Mutex<String>, found: &erwin::probe::Isp) {
    let name = found.name();
    if !ui.get_engine_active() {
        *before.lock().unwrap() = name.clone();
    }
    if ui.get_isp() != name.as_str() {
        ui.set_isp(name.as_str().into());
        ui.set_log(t!("Nhà mạng: {name} (AS{}).", "ISP: {name} (AS{}).", found.asn).into());
    }
}

/// Looks for a newer release off the UI thread. A quiet check only notes what
/// it finds; otherwise the result shows under "Check for updates" and a newer
/// version is offered at once.
fn check_for_update(ui: &MainWindow, w: Weak<MainWindow>, quiet: bool) {
    if ui.get_update_busy() {
        return;
    }
    if !quiet {
        ui.set_update_busy(true);
        ui.set_update_status(tr("Đang kiểm tra bản mới…", "Checking for updates…").into());
    }
    spawn(w, updater::latest, move |ui, res| {
        if !quiet {
            ui.set_update_busy(false);
        }
        match res {
            Ok(latest) if updater::is_newer(&latest) => {
                if ui.get_update_version() != latest.as_str() {
                    ui.set_log(t!("Đã có Yeager {latest}.", "Yeager {latest} is available.").into());
                }
                ui.set_update_version(latest.as_str().into());
                ui.set_update_status(t!("Phiên bản hiện tại {}", "Current version {}", updater::current()).into());
                if !quiet {
                    ui.set_update_dialog(1);
                }
            }
            Ok(_) if !quiet => {
                ui.set_update_status(t!("Yeager đã là bản mới nhất ({})", "Yeager is up to date ({})", updater::current()).into());
            }
            Err(_) if !quiet => {
                ui.set_update_status(
                    tr(
                        "Chưa kiểm tra được bản mới. Kiểm tra kết nối mạng rồi thử lại",
                        "Could not check for updates. Check the network connection and try again",
                    )
                    .into(),
                );
            }
            _ => {}
        }
    });
}

fn enable_doh(ui: &MainWindow, w: Weak<MainWindow>, choice: hange::Choice, http3: bool) {
    enable_doh_then(ui, w, choice, http3, |_, _, _| {});
}

/// Applies DoH off the UI thread, then calls `then` on the UI thread with
/// whether it worked.
fn enable_doh_then(
    ui: &MainWindow,
    w: Weak<MainWindow>,
    choice: hange::Choice,
    http3: bool,
    then: impl FnOnce(&MainWindow, Weak<MainWindow>, bool) + Send + 'static,
) {
    ui.set_log(tr("Đang bật DNS mã hóa…", "Turning encrypted DNS on…").into());
    let weak = w.clone();
    spawn(w, move || hange::enable(choice, http3), move |ui, res| {
        let ok = res.is_ok();
        show_doh_result(&ui, choice, http3, res);
        then(&ui, weak, ok);
    });
}

fn show_doh_result(ui: &MainWindow, choice: hange::Choice, http3: bool, res: common::Result<hange::Applied>) {
    match res {
        Ok(applied) => {
            let mode = if applied.stub { tr("DNS cục bộ", "local DNS") } else { "DoH Windows" };
            ui.set_dns_status(format!("{} ({mode})", choice_label(choice)).into());
            ui.set_log(
                t!(
                    "Đã bật DNS mã hóa {} ({mode}) trên {}.{}",
                    "Encrypted DNS {} ({mode}) is on for {}.{}",
                    choice_label(choice),
                    applied.interfaces.join(", "),
                    if applied.stub || !http3 {
                        ""
                    } else {
                        tr(" Cổng 53 đang bận nên dùng DoH của Windows.", " Port 53 is busy, so Windows' own DoH is used.")
                    }
                )
                .into(),
            );
        }
        Err(e) => {
            ui.set_dns_status(tr("Lỗi", "Error").into());
            ui.set_log(t!("DNS lỗi: {e}", "DNS error: {e}").into());
        }
    }
}

/// Starts the engine once DoH is in place. TCP tuning is separate (erwin).
fn start_engine(ui: &MainWindow, cfg: &Config) {
    ui.set_log(tr("Đang bật engine…", "Starting the engine…").into());
    match engine::start(cfg) {
        Ok(()) => {
            ui.set_engine_active(true);
            ui.set_engine_status(tr("Đang bật", "On").into());
            ui.set_log(tr("Yeager đang chạy (DoH + engine).", "Yeager is running (DoH + engine).").into());
        }
        Err(e) => {
            ui.set_engine_active(false);
            ui.set_engine_status(tr("Lỗi", "Error").into());
            ui.set_log(t!("Không bật được engine: {e}", "Could not start the engine: {e}").into());
        }
    }
}

fn restore_doh(ui: &MainWindow, w: Weak<MainWindow>, done_log: &'static str) {
    ui.set_log(tr("Đang khôi phục DNS…", "Restoring DNS…").into());
    spawn(w, hange::disable, move |ui, ()| {
        ui.set_dns_status(tr("Đã tắt", "Off").into());
        ui.set_log(done_log.into());
    });
}

fn apply_congestion(ui: &MainWindow, w: Weak<MainWindow>, choice: Congestion) {
    ui.set_log(t!("Đang áp dụng {}…", "Applying {}…", choice.label()).into());
    spawn(
        w,
        move || erwin::apply_congestion(choice),
        |ui, res| match res {
            Ok(applied) => {
                let p = applied.provider.to_uppercase();
                ui.set_log(if applied.bbr2_unsupported {
                    t!(
                        "Windows này chưa có BBRv2 (cần Windows 11 22H2 trở lên), đang dùng {p}.",
                        "This Windows has no BBRv2 (needs Windows 11 22H2 or later), using {p}."
                    )
                    .into()
                } else if let Some(reason) = applied.auto_reason {
                    t!("Tự động chọn {p}: {reason}.", "Automatically picked {p}: {reason}.").into()
                } else {
                    t!("Đã áp dụng: {p}", "Applied: {p}").into()
                });
                ui.set_congestion(applied.provider.into());
            }
            Err(e) => ui.set_log(t!("Lỗi: {e}", "Error: {e}").into()),
        },
    );
}

/// Re-renders the status texts Rust set, after a language switch. The labels
/// in the .slint files follow `Lang` on their own.
fn refresh_texts(ui: &MainWindow, cfg: &Config) {
    ui.set_engine_status(if ui.get_engine_active() { tr("Đang bật", "On") } else { tr("Đang tắt", "Off") }.into());
    if !cfg.doh_enabled {
        ui.set_dns_status(tr("Đã tắt", "Off").into());
    } else if hange::is_enabled() {
        let mode = if hange::stub_running() { tr("DNS cục bộ", "local DNS") } else { "DoH Windows" };
        ui.set_dns_status(format!("{} ({mode})", choice_label(dns_choice(cfg))).into());
    }
    if !ui.get_diag_running() && ui.get_diag_pick() < 0 {
        ui.set_diag_status(
            tr(
                "So sánh CUBIC, CTCP và BBRv2 bằng tải thử (~25 MB mỗi loại, khoảng 40 giây)",
                "Compares CUBIC, CTCP and BBRv2 with a test download (~25 MB each, about 40 seconds)",
            )
            .into(),
        );
    }
    if !ui.get_update_busy() {
        ui.set_update_status(t!("Phiên bản hiện tại {}", "Current version {}", updater::current()).into());
    }
    ui.set_log(tr("Đã chuyển sang tiếng Việt.", "Switched to English.").into());
}

const REPO_URL: &str = "https://github.com/iamcino/Yeager";
const GITLAB_URL: &str = "https://gitlab.com/cino-group/yeager";

/// Latency of each DNS provider, for the home and DNS pages.
///
/// The provider the local DNS is using is never probed: its route and
/// latency come from the queries it already answers. The others are measured
/// with one small query per address and transport, only when the DNS page is
/// open (at most every two minutes), or every five minutes for the home page when
/// the local DNS is off.
#[derive(Default)]
struct DnsStats {
    /// Per [`DohProvider::ALL`]: not measured, no answer, or the quickest route.
    measured: [Option<Option<hange::Stat>>; DohProvider::ALL.len()],
    measured_at: Option<std::time::Instant>,
    measuring: bool,
    /// Whether the backup was answering at the last refresh.
    on_backup: bool,
}

const DNS_PAGE: i32 = 4;

fn refresh_dns_stats(ui: &MainWindow, cfg: &Config, stats: &Arc<Mutex<DnsStats>>) {
    let live = hange::status();
    let mut st = stats.lock().unwrap();

    let on_dns_page = ui.get_page() == DNS_PAGE;
    let every = Duration::from_secs(if on_dns_page { 120 } else { 300 });
    let due = st.measured_at.is_none_or(|at| at.elapsed() >= every);
    let wanted: Vec<DohProvider> = if on_dns_page {
        DohProvider::ALL.into_iter().filter(|&p| live.is_none_or(|s| s.provider != p || s.stat.is_none())).collect()
    } else if live.is_none() {
        vec![hange::system_provider(dns_choice(cfg))]
    } else {
        Vec::new()
    };
    if due && !st.measuring && !wanted.is_empty() {
        st.measuring = true;
        // Windows' own DoH (local DNS off) speaks HTTP/2 only.
        let http3 = cfg.doh_http3;
        let stats = stats.clone();
        spawn(
            ui.as_weak(),
            move || wanted.into_iter().map(|p| (p, hange::measure(p, http3))).collect::<Vec<_>>(),
            move |ui, results| {
                {
                    let mut st = stats.lock().unwrap();
                    for (p, stat) in results {
                        if let Some(i) = DohProvider::ALL.iter().position(|&q| q == p) {
                            st.measured[i] = Some(stat);
                        }
                    }
                    st.measured_at = Some(std::time::Instant::now());
                    st.measuring = false;
                }
                show_dns_stats(&ui, hange::status(), &stats.lock().unwrap(), None);
            },
        );
    }
    show_dns_stats(ui, live, &st, Some(cfg));
    st.on_backup = live.is_some_and(|s| s.on_backup);
}

/// Puts `stats` on screen. With `cfg`, also says when the backup provider
/// takes over or gives way.
fn show_dns_stats(ui: &MainWindow, live: Option<hange::PoolStatus>, stats: &DnsStats, cfg: Option<&Config>) {
    let route = |stat: hange::Stat| format!("{} · {} ms", stat.transport.label(), stat.rtt.as_millis());
    let rows: Vec<SharedString> = DohProvider::ALL
        .iter()
        .zip(&stats.measured)
        .map(|(&p, measured)| {
            let stat = live.filter(|s| s.provider == p).and_then(|s| s.stat).or(measured.flatten());
            match (stat, measured) {
                (Some(stat), _) => route(stat),
                (None, Some(None)) => tr("không phản hồi", "no answer").to_string(),
                _ => "—".to_string(),
            }
            .into()
        })
        .collect();
    ui.set_dns_stats(ModelRc::new(VecModel::from(rows)));

    let in_use = live.and_then(|s| Some((s.provider, s.stat?)));
    ui.set_dns_auto_detail(match in_use.filter(|_| ui.get_doh_provider() < 0) {
        Some((p, stat)) => t!("Đang dùng {} · {}", "Using {} · {}", p.label(), route(stat)),
        None => tr("Cloudflare hoặc Google, bên nào nhanh hơn", "Cloudflare or Google, whichever is faster").to_string(),
    }
    .into());

    let home = in_use.or_else(|| {
        let provider = hange::system_provider(dns_choice(cfg?));
        let i = DohProvider::ALL.iter().position(|&p| p == provider)?;
        Some((DohProvider::ALL[i], stats.measured[i].flatten()?))
    });
    if let Some((p, stat)) = home {
        ui.set_dns_ping(format!("{} ms · {} · {}", stat.rtt.as_millis(), stat.transport.label(), p.label()).into());
    }

    if let (Some(cfg), Some(live)) = (cfg, live) {
        if live.on_backup && !stats.on_backup {
            let chosen = cfg.doh_provider;
            let mut text = t!("{} không phản hồi, tạm dùng {}", "{} is not answering, using {} for now", chosen.label(), live.provider.label());
            if chosen == DohProvider::AdGuard {
                text += tr(" (không chặn quảng cáo)", " (ads not blocked)");
            }
            ui.set_dns_status(text.clone().into());
            ui.set_log(text.into());
        } else if !live.on_backup && stats.on_backup {
            ui.set_dns_status(format!("{} ({})", choice_label(dns_choice(cfg)), tr("DNS cục bộ", "local DNS")).into());
            ui.set_log(t!("{} đã phản hồi trở lại.", "{} is answering again.", cfg.doh_provider.label()).into());
        }
    }
}

/// Puts back the TCP settings Yeager changed.
fn restore_tcp(w: Weak<MainWindow>, done_log: &'static str) {
    spawn(
        w,
        || erwin::restore().map(|_| provider_label(erwin::current_provider())),
        move |ui, res| match res {
            Ok(p) => {
                ui.set_congestion(p.into());
                ui.set_log(done_log.into());
            }
            Err(e) => ui.set_log(t!("Không khôi phục được TCP: {e}", "Could not restore TCP: {e}").into()),
        },
    );
}

fn set_tcp_enabled(ui: &MainWindow, cfg: &RefCell<Config>, on: bool) {
    cfg.borrow_mut().tcp_enabled = on;
    config::save(&cfg.borrow());
    ui.set_tcp_enabled(on);
}

/// `#rrggbb` as a color; `None` for anything else.
fn parse_hex_color(s: &str) -> Option<slint::Color> {
    let hex = s.strip_prefix('#').filter(|h| h.len() == 6)?;
    let v = u32::from_str_radix(hex, 16).ok()?;
    Some(slint::Color::from_rgb_u8((v >> 16) as u8, (v >> 8) as u8, v as u8))
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    chars.next().map_or_else(String::new, |c| c.to_uppercase().chain(chars).collect())
}

/// The provider name for the UI, or "?" when `netsh` could not be read.
fn provider_label(provider: Option<String>) -> String {
    provider.unwrap_or_else(|| "?".into())
}

fn set_hosts(ui: &MainWindow, cfg: &Config) {
    let hosts: Vec<SharedString> = cfg.selected_hosts.iter().map(SharedString::from).collect();
    ui.set_hosts(ModelRc::new(VecModel::from(hosts)));
}

fn set_excluded_domains(ui: &MainWindow, cfg: &Config) {
    let domains: Vec<SharedString> = cfg.custom_excluded_domains.iter().map(SharedString::from).collect();
    ui.set_excluded_domains(ModelRc::new(VecModel::from(domains)));
}

fn set_domain_lists(ui: &MainWindow, cfg: &Config) {
    set_hosts(ui, cfg);
    set_excluded_domains(ui, cfg);
}

/// The list a domain sheet edits: 1 Custom exclusions, 2 Selected hosts.
fn domain_list(cfg: &mut Config, sheet: i32) -> &mut Vec<String> {
    if sheet == 1 { &mut cfg.custom_excluded_domains } else { &mut cfg.selected_hosts }
}

/// The suggestions the Selected hosts sheet imports: "game", "remote" or "all".
fn suggested_domains(kind: &str) -> Vec<&'static str> {
    match kind {
        "remote" => levi::REMOTE_TOOL_DOMAINS.to_vec(),
        "game" => levi::GAME_PLATFORM_DOMAINS.to_vec(),
        _ => levi::UNIFIED_COMPAT_DOMAINS.to_vec(),
    }
}

fn transport_profile_index(profile: TransportProfile) -> i32 {
    TransportProfile::ALL.iter().position(|&p| p == profile).unwrap_or(0) as i32
}

fn refresh_engine_stats(ui: &MainWindow) {
    let (_, stabilized, rsts) = engine::get_telemetry();
    ui.set_stats_stabilized(i32::try_from(stabilized).unwrap_or(i32::MAX));
    ui.set_stats_rst_silenced(i32::try_from(rsts).unwrap_or(i32::MAX));
    ui.set_stats_untouched(i32::try_from(levi::total_untouched()).unwrap_or(i32::MAX));
}

/// Hands the domain lists and the Compatibility Mode switch to the engine.
/// A running engine applies them to new connections without a restart and
/// keeps the open ones; a stopped engine reads them again when it starts.
fn apply_lists(cfg: &Config) {
    levi::update_lists(&cfg.selected_hosts, &cfg.custom_excluded_domains, cfg.compatibility_mode_enabled);
}

/// The engine reads the scope and transport profile when it starts, so
/// restart it to apply a change made while it is running.
fn restart_engine_if_active(ui: &MainWindow, cfg: &Config) {
    if !ui.get_engine_active() {
        return;
    }
    engine::stop();
    if let Err(e) = engine::start(cfg) {
        ui.set_engine_active(false);
        ui.set_engine_status(tr("Lỗi", "Error").into());
        ui.set_log(t!("Không bật lại được: {e}", "Could not restart: {e}").into());
    }
}

#[cfg(test)]
mod geometry_tests {
    use super::*;

    #[test]
    fn corrupted_default_migration_falls_back_as_pair() {
        // [0,0], [1,1], one undersized dimension, huge: all fall back as a
        // pair to preferred, never clamped into a minimum-size window.
        assert_eq!(startup_window_size(Some([0, 0])), (860.0, 600.0));
        assert_eq!(startup_window_size(Some([1, 1])), (860.0, 600.0));
        assert_eq!(startup_window_size(Some([100, 600])), (860.0, 600.0));
        assert_eq!(startup_window_size(Some([860, 100])), (860.0, 600.0));
        assert_eq!(startup_window_size(Some([99999, 99999])), (860.0, 600.0));
        assert_eq!(startup_window_size(None), (860.0, 600.0));
    }

    #[test]
    fn deliberate_minimum_size_persists_and_restores() {
        // Minimum size alone is not corruption: 700x500 round-trips.
        assert_eq!(startup_window_size(Some([700, 500])), (700.0, 500.0));
        assert!(should_accept_geometry(true, false, false, true, 1.0, 700.0, 500.0));
    }

    #[test]
    fn minimized_maximized_transient_close_does_not_overwrite() {
        // Minimized, maximized, invisible, uninitialized, bad scale and
        // transient zero/below-minimum snapshots are all rejected.
        assert!(!should_accept_geometry(true, true, false, true, 1.0, 860.0, 600.0));
        assert!(!should_accept_geometry(true, false, true, true, 1.0, 860.0, 600.0));
        assert!(!should_accept_geometry(false, false, false, true, 1.0, 860.0, 600.0));
        assert!(!should_accept_geometry(true, false, false, false, 1.0, 860.0, 600.0));
        assert!(!should_accept_geometry(true, false, false, true, 0.0, 860.0, 600.0));
        assert!(!should_accept_geometry(true, false, false, true, f32::NAN, 860.0, 600.0));
        assert!(!should_accept_geometry(true, false, false, true, 1.0, 0.0, 0.0));
        assert!(!should_accept_geometry(true, false, false, true, 1.0, 1.0, 1.0));
        assert!(!should_accept_geometry(true, false, false, true, 1.0, 100.0, 600.0));
    }

    #[test]
    fn stored_last_known_good_unchanged_for_rejects_via_remember() {
        // The store step itself (not only the predicate) leaves a stored
        // last-known-good unchanged for minimized, maximized and transient
        // rejects.
        let mut stored = Some([900, 650]);
        for (visible, minimized, maximized, initialized, scale, w, h) in [
            (true, true, false, true, 1.0, 860.0, 600.0),
            (true, false, true, true, 1.0, 860.0, 600.0),
            (false, false, false, true, 1.0, 860.0, 600.0),
            (true, false, false, false, 1.0, 860.0, 600.0),
            (true, false, false, true, 0.0, 860.0, 600.0),
            (true, false, false, true, 1.0, 0.0, 0.0),
            (true, false, false, true, 1.0, 100.0, 600.0),
        ] {
            assert!(
                !try_update_geometry(
                    &mut stored,
                    visible,
                    minimized,
                    maximized,
                    initialized,
                    scale,
                    w,
                    h
                ),
                "reject must not update stored"
            );
            assert_eq!(stored, Some([900, 650]), "stored LKG must survive reject");
        }
        // A valid deliberate resize, including 700x500, does update.
        assert!(try_update_geometry(
            &mut stored,
            true,
            false,
            false,
            true,
            1.0,
            700.0,
            500.0
        ));
        assert_eq!(stored, Some([700, 500]));
    }

    #[test]
    fn settled_sample_holds_lkg_for_transient_and_min_max() {
        // Full settled core (with debounce bypassed via force) still holds
        // LKG for minimized / maximized / transient rejects.
        let mut stored = Some([900, 650]);
        let mut tr = GeometryTracker {
            last_known_good: Some([900, 650]),
            initialized: true,
            last_scale: Some(1.0),
            last_work_area: Some((1920.0, 1080.0)),
            pending: None,
            pending_since: None,
        };
        let now = Instant::now();
        for (min, max, w, h) in [(true, false, 860.0, 600.0), (false, true, 860.0, 600.0), (false, false, 0.0, 0.0)]
        {
            assert!(
                !remember_window_size_sample(
                    &mut stored,
                    &mut tr,
                    true,
                    min,
                    max,
                    1.0,
                    w,
                    h,
                    Some((1920.0, 1080.0)),
                    now,
                    true
                )
            );
            assert_eq!(stored, Some([900, 650]));
            assert_eq!(tr.last_known_good, Some([900, 650]));
        }
    }

    #[test]
    fn debounce_fires_only_after_quiet() {
        // Polls do not persist in-progress drag samples: the first sighting
        // arms pending, the commit fires only after GEOMETRY_QUIET.
        let mut stored = Some([860, 600]);
        let mut tr = GeometryTracker {
            last_known_good: Some([860, 600]),
            initialized: true,
            last_scale: Some(1.0),
            last_work_area: Some((1920.0, 1080.0)),
            pending: None,
            pending_since: None,
        };
        let t0 = Instant::now();
        assert!(!remember_window_size_sample(
            &mut stored,
            &mut tr,
            true,
            false,
            false,
            1.0,
            900.0,
            650.0,
            Some((1920.0, 1080.0)),
            t0,
            false
        ));
        assert_eq!(stored, Some([860, 600]));
        // Still moving: same candidate before quiet -> no commit.
        assert!(!remember_window_size_sample(
            &mut stored,
            &mut tr,
            true,
            false,
            false,
            1.0,
            900.0,
            650.0,
            Some((1920.0, 1080.0)),
            t0,
            false
        ));
        assert_eq!(stored, Some([860, 600]));
        // Quiet: same candidate after the interval commits.
        let t1 = t0 + GEOMETRY_QUIET + Duration::from_millis(50);
        assert!(remember_window_size_sample(
            &mut stored,
            &mut tr,
            true,
            false,
            false,
            1.0,
            900.0,
            650.0,
            Some((1920.0, 1080.0)),
            t1,
            false
        ));
        assert_eq!(stored, Some([900, 650]));
        assert_eq!(tr.last_known_good, Some([900, 650]));
    }

    #[test]
    fn skips_saves_across_dpi_or_work_area_transition() {
        let mut stored = Some([860, 600]);
        let mut tr = GeometryTracker {
            last_known_good: Some([860, 600]),
            initialized: true,
            last_scale: Some(1.0),
            last_work_area: Some((1920.0, 1080.0)),
            pending: None,
            pending_since: None,
        };
        let now = Instant::now();
        // DPI jump: skip, update baseline, clear pending.
        assert!(!remember_window_size_sample(
            &mut stored,
            &mut tr,
            true,
            false,
            false,
            1.25,
            860.0,
            600.0,
            Some((1920.0, 1080.0)),
            now,
            false
        ));
        assert_eq!(stored, Some([860, 600]));
        assert_eq!(tr.last_scale, Some(1.25));
        // Work-area jump: skip as well.
        assert!(!remember_window_size_sample(
            &mut stored,
            &mut tr,
            true,
            false,
            false,
            1.25,
            860.0,
            600.0,
            Some((1536.0, 864.0)),
            now,
            true
        ));
        assert_eq!(stored, Some([860, 600]));
    }

    #[test]
    fn work_area_constrained_snapshot_does_not_overwrite_valid_loaded() {
        // Live 800x600 is exactly clamp(900x650 -> 800x600): constrained.
        assert!(is_work_area_constrained_snapshot(
            [800, 600],
            Some([900, 650]),
            Some((800.0, 600.0))
        ));
        assert!(!is_work_area_constrained_snapshot(
            [900, 650],
            Some([900, 650]),
            Some((800.0, 600.0))
        ));
        // Settled core holds the valid loaded size in that case.
        let mut stored = Some([900, 650]);
        let mut tr = GeometryTracker {
            last_known_good: Some([900, 650]),
            initialized: true,
            last_scale: Some(1.0),
            last_work_area: Some((800.0, 600.0)),
            pending: None,
            pending_since: None,
        };
        assert!(!remember_window_size_sample(
            &mut stored,
            &mut tr,
            true,
            false,
            false,
            1.0,
            800.0,
            600.0,
            Some((800.0, 600.0)),
            Instant::now(),
            true
        ));
        assert_eq!(stored, Some([900, 650]));
    }

    #[test]
    fn valid_normal_resize_round_trips() {
        assert!(should_accept_geometry(true, false, false, true, 1.0, 900.0, 650.0));
        assert!(should_accept_geometry(true, false, false, true, 1.25, 859.0, 671.0));
        assert_eq!(startup_window_size(Some([900, 650])), (900.0, 650.0));
    }

    #[test]
    fn write_failure_surfaces_via_save_and_try_save() {
        // Old tests called only helpers that already returned Result while
        // `save` discarded it. Call the top level: `try_save` must Err and
        // `save` must not panic when the config dir cannot be created.
        let anchor = std::env::temp_dir().join(format!(
            "yeager-ui-save-fail-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&anchor, b"not-a-dir").unwrap();
        let prev = std::env::var_os("LOCALAPPDATA");
        unsafe {
            std::env::set_var("LOCALAPPDATA", &anchor);
        }
        let err = erwin::config::try_save(&Config::default()).expect_err("try_save must surface error");
        assert!(!err.to_string().is_empty());
        erwin::config::save(&Config::default());
        unsafe {
            match prev {
                Some(v) => std::env::set_var("LOCALAPPDATA", v),
                None => std::env::remove_var("LOCALAPPDATA"),
            }
        }
        let _ = std::fs::remove_file(&anchor);
    }
}
