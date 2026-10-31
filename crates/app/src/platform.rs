//! Windows-only platform glue: the system tray (icon + context menu), the
//! window/taskbar icon, and DWM rounded corners plus a Mica backdrop so the
//! frameless window matches the EasyKey design language.

use crate::{MainWindow, Theme};
use common::lang::tr;
use common::t;
use muda::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use slint::{ComponentHandle, Model, Weak};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::{Duration, Instant};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::HiDpi::{GetDpiForSystem, GetDpiForWindow, GetSystemMetricsForDpi};
use windows_sys::Win32::UI::WindowsAndMessaging::{SM_CXICON, SM_CXSMICON};

/// Resource id of the application icon embedded by `build.rs`.
const ICON_RESOURCE: u16 = 1;

/// The tray icon and the menu items we react to by id.
pub struct TrayState {
    tray: TrayIcon,
    toggle: CheckMenuItem,
    engine: MenuItem,
    tcp: MenuItem,
    dns: MenuItem,
    open: MenuItem,
    update: MenuItem,
    quit: MenuItem,
    /// What the menu and tooltip last showed, to update them on change.
    shown: RefCell<Option<Shown>>,
    /// What the icon last showed: lit in this accent while on, and whether it
    /// carries the update badge. Kept apart from `shown` because setting the
    /// icon fails while the taskbar is not up yet (start with Windows), and
    /// must then be retried until it sticks.
    icon: RefCell<Option<(Option<slint::Color>, bool)>>,
    /// When setting the icon last failed, to retry once a second, not every tick.
    icon_failed: Cell<Option<Instant>>,
}

/// The state the tray reflects: on/off, theme, and every menu text (which
/// already carry the language).
#[derive(PartialEq)]
struct Shown {
    active: bool,
    /// The UI accent, which the tray icon's rim lights up in while on.
    accent: slint::Color,
    /// A newer version is out.
    update: bool,
    dark: bool,
    texts: [String; 7],
}

/// Builds the tray icon and starts a timer that pumps tray + menu events into
/// the UI. The returned value must be kept alive for the tray to exist.
pub fn setup(ui: &MainWindow) -> Option<Rc<TrayState>> {
    // Texts are filled in by `pump`, in the current language. Like EasyKey's:
    // the switch on top with a check mark, then what is running (each opens
    // its page), then the window, updates and quit.
    let toggle = CheckMenuItem::new("", true, false, None);
    let engine = MenuItem::new("", true, None);
    let tcp = MenuItem::new("", true, None);
    let dns = MenuItem::new("", true, None);
    let open = MenuItem::new("", true, None);
    let update = MenuItem::new("", true, None);
    let quit = MenuItem::new("", true, None);

    let menu = Menu::new();
    menu.append_items(&[
        &toggle,
        &PredefinedMenuItem::separator(),
        &engine,
        &tcp,
        &dns,
        &PredefinedMenuItem::separator(),
        &open,
        &update,
        &PredefinedMenuItem::separator(),
        &quit,
    ])
    .ok()?;

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        // Left click opens the window; the menu belongs to the right click.
        .with_menu_on_left_click(false)
        .with_tooltip("Yeager")
        .with_icon(tray_icon(None, false))
        .build()
        .ok()?;

    let state = Rc::new(TrayState { tray, toggle, engine, tcp, dns, open, update, quit, shown: RefCell::new(None), icon: RefCell::new(None), icon_failed: Cell::new(None) });

    // Poll the tray/menu channels on the UI thread.
    let w = ui.as_weak();
    let st = state.clone();
    let timer = Box::leak(Box::new(slint::Timer::default()));
    timer.start(slint::TimerMode::Repeated, Duration::from_millis(30), move || {
        pump(&w, &st);
    });

    Some(state)
}

fn pump(w: &Weak<MainWindow>, st: &TrayState) {
    let Some(ui) = w.upgrade() else { return };

    // Drain everything queued since the last tick, not just one event.
    while let Ok(ev) = MenuEvent::receiver().try_recv() {
        let open_page = |page| {
            show(&ui);
            ui.set_page(page);
        };
        if ev.id() == st.toggle.id() {
            let next = !ui.get_engine_active();
            ui.invoke_toggle_engine(next);
        } else if ev.id() == st.engine.id() {
            open_page(2);
        } else if ev.id() == st.tcp.id() {
            open_page(3);
        } else if ev.id() == st.dns.id() {
            open_page(4);
        } else if ev.id() == st.open.id() {
            show(&ui);
        } else if ev.id() == st.update.id() {
            // Offer the version a check found, or look for one.
            show(&ui);
            if ui.get_update_version().is_empty() {
                ui.set_page(1);
                ui.invoke_check_update();
            } else {
                ui.set_update_dialog(1);
            }
        } else if ev.id() == st.quit.id() {
            let _ = slint::quit_event_loop();
        }
    }
    while let Ok(ev) = TrayIconEvent::receiver().try_recv() {
        match ev {
            TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. }
            | TrayIconEvent::DoubleClick { button: MouseButton::Left, .. } => show(&ui),
            _ => {}
        }
    }

    // Keep the menu, tooltip and icon in step with the app.
    let now = shown(&ui);

    // The rim lights up in the accent while Yeager is on, so it is noticed in
    // the tray, and a green arrow shows when an update is out. Only recorded
    // once Windows took it: at logon the taskbar may not exist yet, and the
    // tray re-adds whatever icon it last accepted when the taskbar appears.
    let icon = (now.active.then_some(now.accent), now.update);
    let retry = st.icon_failed.get().is_none_or(|at| at.elapsed() >= Duration::from_secs(1));
    if *st.icon.borrow() != Some(icon) && retry {
        if st.tray.set_icon(Some(tray_icon(icon.0, icon.1))).is_ok() {
            *st.icon.borrow_mut() = Some(icon);
            st.icon_failed.set(None);
        } else {
            st.icon_failed.set(Some(Instant::now()));
        }
    }

    let last = st.shown.borrow_mut().take();
    if last.as_ref() != Some(&now) {
        if last.as_ref().map(|l| l.dark) != Some(now.dark) {
            set_menu_theme(now.dark);
        }
        let [toggle, engine, tcp, dns, open, update, quit] = &now.texts;
        // A click flips the check itself; put it back to the real state.
        st.toggle.set_checked(now.active);
        st.toggle.set_text(toggle);
        st.engine.set_text(engine);
        st.tcp.set_text(tcp);
        st.dns.set_text(dns);
        st.open.set_text(open);
        st.update.set_text(update);
        st.quit.set_text(quit);
        let mut tip = format!("Yeager · {}", ui.get_engine_status());
        if !ui.get_update_version().is_empty() {
            tip += &t!(" · có bản {}", " · version {} is out", ui.get_update_version());
        }
        let _ = st.tray.set_tooltip(Some(tip));
    } else if st.toggle.is_checked() != now.active {
        st.toggle.set_checked(now.active);
    }
    *st.shown.borrow_mut() = Some(now);
}

/// What the tray should show now, in the current language.
fn shown(ui: &MainWindow) -> Shown {
    let active = ui.get_engine_active();
    let scope = if ui.get_scope() == 0 {
        tr("Toàn bộ", "All").to_string()
    } else {
        t!("{} tên miền", "{} domains", ui.get_hosts().row_count())
    };
    let engine = if active { scope } else { tr("Tắt", "Off").to_string() };
    let tcp = if ui.get_tcp_enabled() { ui.get_congestion().to_uppercase() } else { tr("Tắt", "Off").to_string() };
    let dns = if ui.get_doh_enabled() { ui.get_dns_status().to_string() } else { tr("Tắt", "Off").to_string() };
    let update = ui.get_update_version();
    Shown {
        active,
        accent: ui.global::<Theme>().get_accent(),
        update: !update.is_empty(),
        dark: ui.get_dark(),
        texts: [
            tr("Bật Yeager", "Yeager on").to_string(),
            format!("Engine: {engine}"),
            format!("TCP: {tcp}"),
            format!("DNS: {dns}"),
            tr("Mở Yeager…", "Open Yeager…").to_string(),
            if update.is_empty() {
                tr("Kiểm tra cập nhật…", "Check for updates…").to_string()
            } else {
                t!("↑ Cập nhật lên {}", "↑ Update to {}", update)
            },
            tr("Thoát Yeager", "Quit Yeager").to_string(),
        ],
    }
}

/// Makes Windows draw the tray menu dark or light to match the app, the way
/// EasyKey does: Explorer's dark menus come from two undocumented uxtheme
/// exports (by ordinal), there since Windows 10 1903.
fn set_menu_theme(dark: bool) {
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
    const SET_PREFERRED_APP_MODE: usize = 135;
    const FLUSH_MENU_THEMES: usize = 136;
    const FORCE_DARK: i32 = 2;
    const FORCE_LIGHT: i32 = 3;
    let name: Vec<u16> = "uxtheme.dll\0".encode_utf16().collect();
    // SAFETY: uxtheme stays loaded for the life of the process; the ordinals
    // have had these signatures since they were added, and are checked for
    // presence before the calls.
    unsafe {
        let uxtheme = LoadLibraryW(name.as_ptr());
        if uxtheme.is_null() {
            return;
        }
        let set = GetProcAddress(uxtheme, SET_PREFERRED_APP_MODE as *const u8);
        let flush = GetProcAddress(uxtheme, FLUSH_MENU_THEMES as *const u8);
        if let (Some(set), Some(flush)) = (set, flush) {
            let set: unsafe extern "system" fn(i32) -> i32 = std::mem::transmute(set);
            let flush: unsafe extern "system" fn() = std::mem::transmute(flush);
            set(if dark { FORCE_DARK } else { FORCE_LIGHT });
            flush();
        }
    }
}

/// Brings the window back from the tray (or from minimized) to the front.
pub fn show(ui: &MainWindow) {
    let _ = ui.show();
    ui.window().set_minimized(false);
    apply_window_chrome(ui);
    use slint::winit_030::WinitWindowAccessor;
    ui.window().with_winit_window(|win| win.focus_window());
}

/// The tray icon at the small-icon size for the current DPI, with its rim lit
/// in `glow` while Yeager is on, and a small green arrow top right when `update`
/// is out.
///
/// `tray.bin` (from `tools/make_icons.py`) holds the icon rendered natively at
/// each tray size, so Windows never has to scale it: a little-endian u32
/// count, then per size a u32 size, `size * size * 4` RGBA bytes and a
/// `size * size` rim mask.
fn tray_icon(glow: Option<slint::Color>, update: bool) -> Icon {
    const BIN: &[u8] = include_bytes!("../../../assets/icons/tray.bin");
    let want = unsafe { GetSystemMetricsForDpi(SM_CXSMICON, GetDpiForSystem()) }.max(16) as usize;
    let u32_at = |i: usize| u32::from_le_bytes([BIN[i], BIN[i + 1], BIN[i + 2], BIN[i + 3]]) as usize;

    // The smallest size at least as big as wanted, else the biggest there is.
    let mut pick = None;
    let mut at = 4;
    for _ in 0..u32_at(0) {
        let size = u32_at(at);
        let entry = (size, at + 4);
        if pick.is_none_or(|(best, _)| (best < want && size > best) || (size >= want && size < best)) {
            pick = Some(entry);
        }
        at += 4 + size * size * 5;
    }
    let (size, at) = pick.expect("tray.bin has icons");
    let mut rgba = BIN[at..at + size * size * 4].to_vec();
    if let Some(c) = glow {
        let mask = &BIN[at + size * size * 4..at + size * size * 5];
        for (px, &m) in rgba.chunks_exact_mut(4).zip(mask) {
            let a = m as u32;
            let mix = |base: u8, glow: u8| ((base as u32 * (255 - a) + glow as u32 * a) / 255) as u8;
            px[0] = mix(px[0], c.red());
            px[1] = mix(px[1], c.green());
            px[2] = mix(px[2], c.blue());
            px[3] = px[3].max(m);
        }
    }
    if update {
        update_badge(&mut rgba, size);
    }
    Icon::from_rgba(rgba, size as u32, size as u32).expect("tray icon")
}

/// Paints a small green up arrow over the top-right corner of a `size` x `size`
/// RGBA icon, with a soft green glow around it so it stands out on both light
/// and dark taskbars. Drawn per size (4x4 supersampled) so it stays sharp at
/// every DPI.
fn update_badge(rgba: &mut [u8], size: usize) {
    const CORE: [f32; 3] = [0x5c as f32, 0xf2 as f32, 0x7e as f32];
    const GLOW: [f32; 3] = [0x34 as f32, 0xc7 as f32, 0x59 as f32];
    // An up arrow in a unit box: head, then shaft.
    const ARROW: [(f32, f32); 7] =
        [(0.5, 0.0), (1.0, 0.5), (0.7, 0.5), (0.7, 1.0), (0.3, 1.0), (0.3, 0.5), (0.0, 0.5)];
    let n = size as f32;
    // About a fifth of the icon, but never under 6 px or it stops reading as
    // an arrow at 16 px.
    let box_size = (n / 5.0).max(6.0);
    let glow = (box_size * 0.4).max(1.5);
    let (left, top) = (n - box_size - glow * 0.6, glow * 0.6);
    let pts: Vec<(f32, f32)> = ARROW.iter().map(|&(x, y)| (left + x * box_size, top + y * box_size)).collect();

    let inside = |x: f32, y: f32| {
        let mut odd = false;
        for i in 0..pts.len() {
            let (a, b) = (pts[i], pts[(i + 1) % pts.len()]);
            if (a.1 > y) != (b.1 > y) && x < a.0 + (y - a.1) * (b.0 - a.0) / (b.1 - a.1) {
                odd = !odd;
            }
        }
        odd
    };
    let distance = |x: f32, y: f32| {
        (0..pts.len())
            .map(|i| {
                let (a, b) = (pts[i], pts[(i + 1) % pts.len()]);
                let (dx, dy) = (b.0 - a.0, b.1 - a.1);
                let t = (((x - a.0) * dx + (y - a.1) * dy) / (dx * dx + dy * dy)).clamp(0.0, 1.0);
                let (px, py) = (a.0 + t * dx - x, a.1 + t * dy - y);
                (px * px + py * py).sqrt()
            })
            .fold(f32::MAX, f32::min)
    };

    let blend = |p: &mut [u8], color: [f32; 3], cover: f32| {
        for i in 0..3 {
            p[i] = (p[i] as f32 * (1.0 - cover) + color[i] * cover).round() as u8;
        }
        p[3] = (p[3] as f32 + (255.0 - p[3] as f32) * cover).round() as u8;
    };
    for py in 0..size {
        for px in 0..size {
            let (mut fill, mut halo) = (0.0f32, 0.0f32);
            for sy in 0..4 {
                for sx in 0..4 {
                    let (x, y) = (px as f32 + (sx as f32 + 0.5) / 4.0, py as f32 + (sy as f32 + 0.5) / 4.0);
                    if inside(x, y) {
                        fill += 1.0 / 16.0;
                    } else {
                        let d = distance(x, y);
                        if d < glow {
                            halo += 0.75 * (1.0 - d / glow).powi(2) / 16.0;
                        }
                    }
                }
            }
            if fill + halo == 0.0 {
                continue;
            }
            let p = &mut rgba[(py * size + px) * 4..][..4];
            blend(p, GLOW, halo);
            blend(p, CORE, fill);
        }
    }
}

/// Returns the native handle of the Slint window, once it has been created.
fn hwnd(ui: &MainWindow) -> Option<HWND> {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use slint::winit_030::WinitWindowAccessor;
    ui.window()
        .with_winit_window(|win| match win.window_handle().ok()?.as_raw() {
            RawWindowHandle::Win32(h) => Some(h.hwnd.get() as HWND),
            _ => None,
        })
        .flatten()
}

/// Sets the title-bar/taskbar icons from the embedded `.ico` at the sizes
/// Windows asks for at this window's DPI, then applies rounded corners and a
/// Mica backdrop. Needs the window to be shown, so call it after `show()`.
pub fn apply_window_chrome(ui: &MainWindow) {
    use windows_sys::Win32::Graphics::Dwm::{
        DwmSetWindowAttribute, DWMWCP_ROUND, DWMWA_SYSTEMBACKDROP_TYPE, DWMWA_WINDOW_CORNER_PREFERENCE,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        LoadImageW, SendMessageW, ICON_BIG, ICON_SMALL, IMAGE_ICON, LR_DEFAULTCOLOR, WM_SETICON,
    };

    const DWMSBT_MAINWINDOW: i32 = 2; // Mica

    let Some(hwnd) = hwnd(ui) else { return };
    unsafe {
        let dpi = GetDpiForWindow(hwnd);
        let module = GetModuleHandleW(std::ptr::null());
        for (kind, metric) in [(ICON_SMALL, SM_CXSMICON), (ICON_BIG, SM_CXICON)] {
            let size = GetSystemMetricsForDpi(metric, dpi);
            let icon = LoadImageW(module, ICON_RESOURCE as usize as *const u16, IMAGE_ICON, size, size, LR_DEFAULTCOLOR);
            if !icon.is_null() {
                SendMessageW(hwnd, WM_SETICON, kind as usize, icon as isize);
            }
        }

        let round = DWMWCP_ROUND;
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_WINDOW_CORNER_PREFERENCE as u32,
            &round as *const _ as *const _,
            std::mem::size_of_val(&round) as u32,
        );
        let backdrop = DWMSBT_MAINWINDOW;
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_SYSTEMBACKDROP_TYPE as u32,
            &backdrop as *const _ as *const _,
            std::mem::size_of_val(&backdrop) as u32,
        );
    }
}

/// Marks a running Yeager in this logon session.
const INSTANCE_MUTEX: &str = "Local\\Yeager_SingleInstance_Mutex";
/// Set by a second launch to ask the running Yeager to show its window.
const SHOW_EVENT: &str = "Local\\Yeager_Show";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Holds the single-instance mutex and the show-request event for the process
/// lifetime.
pub struct SingleInstanceGuard {
    mutex: windows_sys::Win32::Foundation::HANDLE,
    show: windows_sys::Win32::Foundation::HANDLE,
}

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        for h in [self.mutex, self.show] {
            if !h.is_null() {
                unsafe { CloseHandle(h) };
            }
        }
    }
}

pub enum SingleInstanceDecision {
    /// Proceed running as the unique instance.
    Proceed(SingleInstanceGuard),
    /// Another instance was asked to show its window; exit immediately.
    AlreadyRunning,
}

/// Makes sure only one Yeager runs per logon session.
///
/// A second launch asks the running instance to show its window and exits.
/// Nothing is ever killed: a killed Yeager leaves its TCP and DNS changes
/// behind. Started by an update (`updated`), the previous exe still holds the
/// mutex while it exits, so wait for it instead of handing over to it.
pub fn ensure_single_instance(updated: bool) -> SingleInstanceDecision {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError};
    use windows_sys::Win32::System::Threading::{CreateEventW, CreateMutexW, SetEvent};
    use windows_sys::Win32::UI::WindowsAndMessaging::{ASFW_ANY, AllowSetForegroundWindow};

    // The event first, so a launch racing our startup still finds it; it stays
    // set until `watch_show_requests` picks it up.
    let show_name = wide(SHOW_EVENT);
    let show = unsafe { CreateEventW(std::ptr::null(), 0, 0, show_name.as_ptr()) };

    let mutex_name = wide(INSTANCE_MUTEX);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mutex = loop {
        let h = unsafe { CreateMutexW(std::ptr::null(), 0, mutex_name.as_ptr()) };
        if h.is_null() || unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
            break h;
        }
        if updated {
            if Instant::now() >= deadline {
                // The old exe hangs on its way out: run anyway rather than
                // leave no Yeager after the update.
                break h;
            }
            unsafe { CloseHandle(h) };
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        unsafe {
            CloseHandle(h);
            if !show.is_null() {
                // We were just launched by the user, so we may pass the
                // foreground on to the running instance.
                AllowSetForegroundWindow(ASFW_ANY);
                SetEvent(show);
                CloseHandle(show);
            }
        }
        return SingleInstanceDecision::AlreadyRunning;
    };

    SingleInstanceDecision::Proceed(SingleInstanceGuard { mutex, show })
}

/// Shows the window whenever a second launch asks for it.
pub fn watch_show_requests(ui: &MainWindow, guard: &SingleInstanceGuard) {
    use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    if guard.show.is_null() {
        return;
    }
    // The guard outlives the UI loop, so the handle stays valid for the timer.
    let event = guard.show as usize;
    let w = ui.as_weak();
    let timer = Box::leak(Box::new(slint::Timer::default()));
    timer.start(slint::TimerMode::Repeated, Duration::from_millis(250), move || {
        if unsafe { WaitForSingleObject(event as _, 0) } == WAIT_OBJECT_0
            && let Some(ui) = w.upgrade()
        {
            show(&ui);
        }
    });
}
