# Yeager — build release binaries and assemble dist\
# Requires: Rust toolchain plus a resource compiler for the embedded
# icon/manifest: `windres` (w64devkit/MSYS2) for the GNU toolchain, or the
# Windows SDK `rc.exe` for MSVC. If Explorer still shows an old icon after a
# rebuild, refresh its icon cache with `ie4uinit.exe -show`.
#
# Builds the GUI (yeager.exe). DNS is backup state and restore inside the app;
# there is no separate service binary. The release pipeline signs and hashes
# the exe under the pinned-certificate policy.

$ErrorActionPreference = "Stop"

Write-Host "Building Yeager (release)..." -ForegroundColor Cyan
cargo build --release -p yeager
if ($LASTEXITCODE -ne 0) { throw "cargo build -p yeager failed" }

$exe = Join-Path $PSScriptRoot "target\release\yeager.exe"
if (-not (Test-Path $exe)) {
    throw "Build did not produce $exe"
}

$dist = Join-Path $PSScriptRoot "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null
Copy-Item $exe (Join-Path $dist "yeager.exe") -Force

$leviExe = Join-Path $PSScriptRoot "target\release\levi.exe"
if (Test-Path $leviExe) {
    Copy-Item $leviExe (Join-Path $dist "levi.exe") -Force
    $leviSize = [math]::Round((Get-Item $leviExe).Length / 1KB, 0)
    Write-Host "Done. dist\levi.exe ($leviSize KB)" -ForegroundColor Yellow
}

$size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Host "Done. dist\yeager.exe ($size MB)" -ForegroundColor Green
