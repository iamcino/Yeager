//! Running Windows system tools (`netsh`, `powershell`, `schtasks`) without
//! flashing a console window.

use crate::{Error, Result};
use std::process::Command;

/// A `Command` that never opens a console window on Windows.
pub fn hidden(program: &str) -> Command {
    #[allow(unused_mut)]
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// Runs a command and returns its stdout, failing on a non-zero exit code.
pub fn run(program: &str, args: &[&str]) -> Result<String> {
    let out = hidden(program)
        .args(args)
        .output()
        .map_err(|e| Error::new(crate::t!("Không chạy được {program}: {e}", "Could not run {program}: {e}")))?;
    if out.status.success() {
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    // PowerShell may prefix stderr with serialized progress records.
    let reason = stderr
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("#< CLIXML") && !l.starts_with("<Objs"));
    Err(Error::new(match reason {
        Some(reason) => format!("{program}: {reason}"),
        None => crate::t!(
            "{program} lỗi ({}). Yeager cần quyền Administrator.",
            "{program} failed ({}). Yeager needs administrator rights.",
            out.status.code().unwrap_or(-1)
        ),
    }))
}

/// Runs a PowerShell command non-interactively.
pub fn powershell(script: &str) -> Result<String> {
    run(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", script],
    )
}
