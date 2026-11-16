//! Clock abstraction for the transaction engine (U03). Journal timestamps are
//! ISO-8601 with second precision (the journal schema); retry delays are
//! tracked in milliseconds, so the clock keeps millisecond resolution and the
//! virtual implementation makes every budget/delay assertion deterministic.

use std::cell::Cell;
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub trait Clock {
    fn now_ms(&self) -> i64;
    fn sleep_ms(&self, ms: u64);
}

/// ISO-8601 UTC, second precision, exactly `YYYY-MM-DDTHH:MM:SSZ`.
pub fn utc_string(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let (y, mo, d) = civil_from_days(secs.div_euclid(86400));
    let rem = secs.rem_euclid(86400);
    format!(
        "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's civil_from_days algorithm (days since 1970-01-01).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }
    fn sleep_ms(&self, ms: u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

/// Deterministic virtual clock. Clones share the same time; `sleep_ms`
/// advances it instead of blocking.
#[derive(Clone)]
pub struct VirtualClock {
    ms: Rc<Cell<i64>>,
}

impl VirtualClock {
    pub fn new(start_ms: i64) -> Self {
        Self { ms: Rc::new(Cell::new(start_ms)) }
    }
    pub fn advance_ms(&self, ms: i64) {
        self.ms.set(self.ms.get() + ms);
    }
    pub fn set_ms(&self, ms: i64) {
        self.ms.set(ms);
    }
}

impl Clock for VirtualClock {
    fn now_ms(&self) -> i64 {
        self.ms.get()
    }
    fn sleep_ms(&self, ms: u64) {
        self.advance_ms(ms as i64);
    }
}
