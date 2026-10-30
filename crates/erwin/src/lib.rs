//! `erwin` — strategy engine.
//!
//! Erwin is the "brain" from the Technical Design Document: it owns the
//! persisted [`Config`] and drives the Windows TCP congestion-control template
//! to match what the user picked. TCP tuning is a signal amplifier for the
//! engine, not a packet path of its own.
//!
//! Every change is undoable: the settings Yeager touches are saved to
//! `tcp-backup.json` before the first change and put back by [`restore`] when
//! the engine stops, when the app exits, or on the next launch after a crash.
//!
//! [`Config`]: common::Config

use common::lang::tr;
use common::{process, t, Congestion, Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

pub mod config;
pub mod latency;
pub mod probe;

use probe::{Download, LinkStats};

/// Serialises apply/restore, which run on worker threads.
pub(crate) static LOCK: Mutex<()> = Mutex::new(());

/// Congestion providers `netsh` can report. They are never localised, unlike
/// the labels next to them, so they are matched by value rather than by label.
const PROVIDERS: [&str; 6] = ["bbr2", "cubic", "ctcp", "dctcp", "newreno", "default"];
/// Pacing profiles, matched the same way.
const PACING: [&str; 4] = ["off", "initialwindow", "slowstart", "always"];

/// The TCP settings Yeager changes, as they were before it changed them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Snapshot {
    provider: String,
    pacing: String,
}

/// What [`apply_congestion`] ended up applying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// The provider Windows reports afterwards.
    pub provider: String,
    /// BBRv2 was asked for but this Windows does not have it, so CUBIC is used.
    pub bbr2_unsupported: bool,
    /// Why `Congestion::Auto` chose what it chose.
    pub auto_reason: Option<String>,
}

/// A recommended controller and why, in words for the user.
#[derive(Debug, Clone, PartialEq)]
pub struct Pick {
    pub choice: Congestion,
    pub reason: String,
}

/// Reads the active congestion-control provider from `netsh`, or `None` if it
/// cannot be read.
pub fn current_provider() -> Option<String> {
    let text = process::run("netsh", &["int", "tcp", "show", "supplemental"]).ok()?;
    find_value(&text, &PROVIDERS)
}

fn current_pacing() -> Option<String> {
    let text = process::run("netsh", &["int", "tcp", "show", "global"]).ok()?;
    find_value(&text, &PACING)
}

/// The first `label : value` line whose value is one of `known`.
fn find_value(text: &str, known: &[&str]) -> Option<String> {
    text.lines()
        .filter_map(|line| line.rsplit_once(':'))
        .map(|(_, value)| value.trim().to_ascii_lowercase())
        .find(|value| known.contains(&value.as_str()))
}

/// Applies a congestion-control provider via `netsh`.
///
/// `Congestion::Auto` pings for about a second and picks with
/// [`pick_from_idle`]; if pings get no answer it uses BBRv2. Windows without
/// BBRv2 (before Windows 11 22H2) falls back to CUBIC.
pub fn apply_congestion(choice: Congestion) -> Result<Applied> {
    let auto = (choice == Congestion::Auto).then(|| {
        probe::ping_all(8, Duration::from_millis(100))
            .ok()
            .and_then(|stats| pick_from_idle(&stats))
            .unwrap_or_else(|| Pick {
                choice: Congestion::Bbr2,
                reason: common::lang::tr("không đo được ping, dùng BBRv2 mặc định", "no ping answers, BBRv2 by default").into(),
            })
    });

    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    ensure_backup()?;

    let wanted = auto.as_ref().map_or(choice, |p| p.choice).provider().unwrap_or("bbr2");
    let mut bbr2_unsupported = false;
    let mut provider = set_provider(wanted).ok().and_then(|_| current_provider());
    if wanted == "bbr2" && provider.as_deref() != Some("bbr2") {
        bbr2_unsupported = true;
        set_provider("cubic")?;
        provider = current_provider();
    }
    let provider = provider.ok_or_else(|| Error::new(common::lang::tr(
        "Không đọc lại được thuật toán TCP sau khi áp dụng.",
        "Could not read the TCP algorithm back after applying it.",
    )))?;

    // Pacing helps BBRv2; it only gets in the way of the loss-based controllers.
    let pacing = if provider == "bbr2" { "always" } else { "off" };
    let _ = set_pacing(pacing);

    Ok(Applied { provider, bbr2_unsupported, auto_reason: auto.map(|p| p.reason) })
}

/// Saves the current settings before Yeager's first change.
fn ensure_backup() -> Result<()> {
    if !backup_path().exists() {
        let snapshot = Snapshot {
            provider: current_provider().unwrap_or_else(|| "cubic".into()),
            pacing: current_pacing().unwrap_or_else(|| "off".into()),
        };
        write_snapshot(&backup_path(), &snapshot)?;
    }
    Ok(())
}

/// Above this share of lost echoes the link counts as lossy.
const LOSSY: f64 = 0.02;
/// Above this jitter (ms) the link counts as unstable, e.g. Wi-Fi or 4G.
const JITTERY_MS: f64 = 10.0;
/// Above this median round trip (ms) the path counts as long.
const FAR_MS: u32 = 100;

/// A quick guess from idle pings: BBRv2 for lossy, unstable or long paths,
/// where it holds throughput better than loss-based CUBIC; CUBIC for a clean,
/// short path, where the two perform alike and CUBIC is Windows' own default.
/// `None` if no echo came back (ICMP blocked).
pub fn pick_from_idle(stats: &LinkStats) -> Option<Pick> {
    let median = stats.median_ms()?;
    let loss = stats.loss();
    let jitter = stats.jitter_ms().unwrap_or(0.0);
    let measured = t!(
        "ping {median} ms, dao động {jitter:.0} ms, mất gói {:.0}%",
        "ping {median} ms, jitter {jitter:.0} ms, loss {:.0}%",
        loss * 100.0
    );
    let (choice, why) = if loss >= LOSSY {
        (Congestion::Bbr2, tr("mạng có mất gói", "packet loss"))
    } else if jitter >= JITTERY_MS {
        (Congestion::Bbr2, tr("độ trễ dao động mạnh", "unstable latency"))
    } else if median >= FAR_MS {
        (Congestion::Bbr2, tr("đường truyền xa", "long-distance link"))
    } else {
        (Congestion::Cubic, tr("mạng ổn định", "stable link"))
    };
    Some(Pick { choice, reason: format!("{why} ({measured})") })
}

/// One controller's result in [`diagnose`].
#[derive(Debug, Clone, PartialEq)]
pub struct Trial {
    pub choice: Congestion,
    pub download: Download,
    pub idle: LinkStats,
    /// Pings sent while the download ran: latency under load (bufferbloat).
    pub loaded: LinkStats,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub trials: Vec<Trial>,
    pub best: Pick,
    /// The network the test ran over, if Cloudflare could tell.
    pub isp: Option<probe::Isp>,
}

const TEST_BYTES: u64 = 25_000_000;
const TEST_TIME: Duration = Duration::from_secs(8);

/// Tries CUBIC, CTCP, then BBRv2 (if this Windows has it): for each, idle
/// pings, then a timed download with pings alongside. Leaves the settings as
/// it found them; the caller applies the recommendation if the user wants it.
/// Takes about 35 s and up to ~85 MB.
pub fn diagnose(progress: impl Fn(String)) -> Result<Report> {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    ensure_backup()?;
    let before = (current_provider(), current_pacing());

    let result = (|| {
        progress(tr("Đang xác định nhà mạng…", "Detecting the ISP…").into());
        let isp = probe::isp().ok(); // also warms DNS and the route
        progress(tr("Đang khởi động phép đo…", "Starting the test…").into());
        let _ = probe::download(2_000_000, Duration::from_secs(3));

        let mut trials = Vec::new();
        for choice in [Congestion::Cubic, Congestion::Ctcp, Congestion::Bbr2] {
            let provider = choice.provider().unwrap_or("cubic");
            if set_provider(provider).is_err() || current_provider().as_deref() != Some(provider) {
                continue; // e.g. BBRv2 missing on this Windows
            }
            let _ = set_pacing(if provider == "bbr2" { "always" } else { "off" });

            progress(t!("Đang đo {}: độ trễ…", "Testing {}: latency…", choice.label()));
            let idle = probe::ping_all(10, Duration::from_millis(100)).unwrap_or_default();

            progress(t!("Đang đo {}: tải thử…", "Testing {}: download…", choice.label()));
            let stop = std::sync::atomic::AtomicBool::new(false);
            let (download, loaded) = std::thread::scope(|s| {
                let pings = s.spawn(|| {
                    probe::ping(probe::PING_TARGETS[0], u32::MAX, Duration::from_millis(200), &stop)
                });
                let download = probe::download(TEST_BYTES, TEST_TIME);
                stop.store(true, std::sync::atomic::Ordering::Relaxed);
                let loaded = pings.join().ok().and_then(|r| r.ok()).unwrap_or_default();
                (download, loaded)
            });
            trials.push(Trial { choice, download: download?, idle, loaded });
        }
        let best = pick_best(&trials).ok_or_else(|| Error::new(tr("Không đo được thuật toán nào.", "No algorithm could be measured.")))?;
        Ok(Report { trials, best, isp })
    })();

    if let Some(provider) = before.0 {
        let _ = set_provider(&provider);
    }
    if let Some(pacing) = before.1 {
        let _ = set_pacing(&pacing);
    }
    result
}

/// The fastest trial, unless another is nearly as fast (within 10%) with
/// clearly lower latency under load (20% or more).
pub fn pick_best(trials: &[Trial]) -> Option<Pick> {
    let mut sorted: Vec<&Trial> = trials.iter().filter(|t| t.download.mbps() > 0.0).collect();
    sorted.sort_by(|a, b| b.download.mbps().total_cmp(&a.download.mbps()));
    let fastest = *sorted.first()?;
    let lag = |t: &Trial| t.loaded.median_ms().or(t.idle.median_ms());
    let calmer = sorted.iter().skip(1).find(|t| {
        t.download.mbps() >= fastest.download.mbps() * 0.9
            && matches!((lag(t), lag(fastest)), (Some(a), Some(b)) if (a as f64) <= b as f64 * 0.8)
    });
    let describe = |t: &Trial| {
        let lag = lag(t).map_or("?".into(), |ms| format!("{ms} ms"));
        t!("{} {:.0} Mbps, trễ khi tải {lag}", "{} {:.0} Mbps, {lag} under load", t.choice.label(), t.download.mbps())
    };
    Some(match calmer {
        Some(t) => Pick {
            choice: t.choice,
            reason: t!(
                "tốc độ gần bằng nhưng trễ thấp hơn: {} so với {}",
                "nearly as fast with lower latency: {} against {}",
                describe(t),
                describe(fastest)
            ),
        },
        None if sorted.len() > 1 => Pick {
            choice: fastest.choice,
            reason: t!("nhanh nhất: {} so với {}", "fastest: {} against {}", describe(fastest), describe(sorted[1])),
        },
        None => Pick { choice: fastest.choice, reason: t!("chỉ đo được {}", "only measured {}", describe(fastest)) },
    })
}

/// Puts back the settings saved before Yeager's first change. Does nothing if
/// Yeager has not changed anything. Returns whether something was restored.
pub fn restore() -> Result<bool> {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = backup_path();
    let Some(snapshot) = read_snapshot(&path) else {
        let _ = std::fs::remove_file(&path);
        return Ok(false);
    };
    set_provider(&snapshot.provider)?;
    let _ = set_pacing(&snapshot.pacing);
    let _ = std::fs::remove_file(&path);
    Ok(true)
}

/// Puts Windows' own defaults back (CUBIC, no pacing), whatever was set before
/// Yeager, and forgets the saved snapshot so nothing is restored over it later.
pub fn reset_defaults() -> Result<()> {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    set_provider("cubic")?;
    let _ = set_pacing("off");
    let _ = std::fs::remove_file(backup_path());
    Ok(())
}

fn set_provider(provider: &str) -> Result<()> {
    process::run(
        "netsh",
        &["int", "tcp", "set", "supplemental", "template=internet", &format!("congestionprovider={provider}")],
    )
    .map(|_| ())
}

fn set_pacing(profile: &str) -> Result<()> {
    process::run("netsh", &["int", "tcp", "set", "global", &format!("pacingprofile={profile}")]).map(|_| ())
}

fn backup_path() -> PathBuf {
    config::dir().join("tcp-backup.json")
}

fn write_snapshot(path: &Path, snapshot: &Snapshot) -> Result<()> {
    let json = serde_json::to_string(snapshot).map_err(|e| Error::new(e.to_string()))?;
    config::write_atomic(path, json.as_bytes())?;
    Ok(())
}

/// The saved snapshot, if it exists and holds values `netsh` accepts.
fn read_snapshot(path: &Path) -> Option<Snapshot> {
    let snapshot: Snapshot = serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    (PROVIDERS.contains(&snapshot.provider.as_str()) && PACING.contains(&snapshot.pacing.as_str()))
        .then_some(snapshot)
}

const TASK_NAME: &str = "Yeager";

/// Registers or removes a logon scheduled task so the elevated app can start at
/// login (a plain Run key cannot elevate at boot).
pub fn set_launch_at_login(enabled: bool, exe: &PathBuf) -> Result<()> {
    if !enabled {
        let _ = process::run("schtasks", &["/Delete", "/TN", TASK_NAME, "/F"]);
        return Ok(());
    }
    let exe = exe.to_string_lossy();
    process::run(
        "schtasks",
        &["/Create", "/TN", TASK_NAME, "/TR", &format!("\"{exe}\""), "/SC", "ONLOGON", "/RL", "HIGHEST", "/F"],
    )
    .map(|_| ())
    .map_err(|e| Error::new(t!("Không đặt được khởi động cùng Windows: {e}", "Could not set up start with Windows: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUPPLEMENTAL_EN: &str = "\
The TCP global default template is internet

TCP Supplemental Parameters
----------------------------------------------
Minimum RTO (msec)                  : 300
Initial Congestion Window (MSS)     : 10
Congestion Control Provider         : BBR2
Enable Congestion Window Restart    : disabled
Delayed Ack Timeout (msec)          : 40
";

    const SUPPLEMENTAL_DE: &str = "\
TCP-Zusatzparameter
----------------------------------------------
Minimales RTO (ms)                       : 300
Anfängliches Überlastungsfenster (MSS)   : 4
Überlastungssteuerungsanbieter           : cubic
Überlastungsfensterneustart aktivieren   : deaktiviert
";

    const GLOBAL_EN: &str = "\
Receive-Side Scaling State          : enabled
Receive Window Auto-Tuning Level    : normal
ECN Capability                      : disabled
Pacing Profile                      : off
";

    #[test]
    fn reads_provider_in_any_language() {
        assert_eq!(find_value(SUPPLEMENTAL_EN, &PROVIDERS).as_deref(), Some("bbr2"));
        assert_eq!(find_value(SUPPLEMENTAL_DE, &PROVIDERS).as_deref(), Some("cubic"));
        assert_eq!(find_value("", &PROVIDERS), None);
    }

    #[test]
    fn reads_pacing() {
        assert_eq!(find_value(GLOBAL_EN, &PACING).as_deref(), Some("off"));
        assert_eq!(find_value(SUPPLEMENTAL_EN, &PACING), None);
    }

    fn trial(choice: Congestion, mbps: u64, lag_ms: u32) -> Trial {
        Trial {
            choice,
            download: Download { bytes: mbps * 1_000_000 / 8, elapsed: Duration::from_secs(1) },
            idle: LinkStats::default(),
            loaded: LinkStats { sent: 3, rtts: vec![lag_ms; 3] },
        }
    }

    #[test]
    fn picks_from_idle_pings() {
        let clean = LinkStats { sent: 16, rtts: vec![20; 16] };
        assert_eq!(pick_from_idle(&clean).unwrap().choice, Congestion::Cubic);
        let lossy = LinkStats { sent: 16, rtts: vec![20; 15] };
        assert_eq!(pick_from_idle(&lossy).unwrap().choice, Congestion::Bbr2);
        let jittery = LinkStats { sent: 4, rtts: vec![20, 60, 20, 60] };
        assert_eq!(pick_from_idle(&jittery).unwrap().choice, Congestion::Bbr2);
        let far = LinkStats { sent: 4, rtts: vec![180; 4] };
        assert_eq!(pick_from_idle(&far).unwrap().choice, Congestion::Bbr2);
        assert_eq!(pick_from_idle(&LinkStats { sent: 8, rtts: vec![] }), None);
    }

    #[test]
    fn picks_best_trial() {
        // Clearly faster wins.
        let t = [trial(Congestion::Cubic, 50, 40), trial(Congestion::Bbr2, 80, 40)];
        assert_eq!(pick_best(&t).unwrap().choice, Congestion::Bbr2);
        // Nearly as fast with much lower latency under load wins.
        let t = [trial(Congestion::Cubic, 100, 200), trial(Congestion::Bbr2, 95, 50)];
        assert_eq!(pick_best(&t).unwrap().choice, Congestion::Bbr2);
        // Nearly as fast but no calmer: the fastest stays.
        let t = [trial(Congestion::Cubic, 100, 50), trial(Congestion::Bbr2, 95, 48)];
        assert_eq!(pick_best(&t).unwrap().choice, Congestion::Cubic);
        assert_eq!(pick_best(&[]), None);
    }

    #[test]
    fn snapshot_round_trips_and_rejects_junk() {
        let dir = std::env::temp_dir().join(format!("erwin-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tcp-backup.json");

        let snapshot = Snapshot { provider: "cubic".into(), pacing: "off".into() };
        write_snapshot(&path, &snapshot).unwrap();
        assert_eq!(read_snapshot(&path), Some(snapshot));

        std::fs::write(&path, r#"{"provider":"cubic & calc","pacing":"off"}"#).unwrap();
        assert_eq!(read_snapshot(&path), None);

        let _ = std::fs::remove_dir_all(dir);
    }
}
