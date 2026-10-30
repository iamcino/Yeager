//! UI language. Every user-facing string is written in both Vietnamese and
//! English next to each other and picked at the moment it is shown, so a
//! switch takes effect on the next message without restarting.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Language {
    #[default]
    Vi,
    En,
}

impl Language {
    /// The Windows display language: Vietnamese if that is what the user
    /// runs, English otherwise.
    pub fn system() -> Self {
        #[cfg(windows)]
        {
            #[link(name = "kernel32")]
            unsafe extern "system" {
                fn GetUserDefaultUILanguage() -> u16;
            }
            const LANG_VIETNAMESE: u16 = 0x2a;
            if unsafe { GetUserDefaultUILanguage() } & 0x3ff == LANG_VIETNAMESE {
                Language::Vi
            } else {
                Language::En
            }
        }
        #[cfg(not(windows))]
        {
            Language::Vi
        }
    }
}

static ENGLISH: AtomicBool = AtomicBool::new(false);

pub fn set(lang: Language) {
    ENGLISH.store(lang == Language::En, Ordering::Relaxed);
}

pub fn current() -> Language {
    if is_en() {
        Language::En
    } else {
        Language::Vi
    }
}

pub fn is_en() -> bool {
    ENGLISH.load(Ordering::Relaxed)
}

/// Picks the string for the current language.
pub fn tr(vi: &'static str, en: &'static str) -> &'static str {
    if is_en() {
        en
    } else {
        vi
    }
}

/// `format!` in the current language: `t!("Đã thêm {host}.", "Added {host}.")`.
#[macro_export]
macro_rules! t {
    ($vi:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        if $crate::lang::is_en() {
            format!($en $(, $arg)*)
        } else {
            format!($vi $(, $arg)*)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_by_language() {
        let n = 3;
        set(Language::En);
        assert_eq!(t!("{n} tên miền", "{n} domains"), "3 domains");
        assert_eq!(tr("Bật", "On"), "On");
        set(Language::Vi);
        assert_eq!(t!("{n} tên miền", "{n} domains"), "3 tên miền");
        assert_eq!(current(), Language::Vi);
    }
}
