# Yeager — build release binaries and assemble dist\
# Requires: Rust toolchain plus a resource compiler for the embedded
# icon/manifest: `windres` (w64devkit/MSYS2) for the GNU toolchain, or the
# Windows SDK `rc.exe` for MSVC. If Explorer still shows an old icon after a
# rebuild, refresh its icon cache with `ie4uinit.exe -show`.
#
# U09: builds BOTH the GUI (yeager.exe) and the privileged DNS recovery
# service (yeager-dns-recovery.exe). Both ship in the installer and inside
# the portable zip (docs/DNS-RECOVERY.md); the release pipeline signs and
# hashes both under the same pinned-certificate policy.

$ErrorActionPreference = "Stop"

Write-Host "Building Yeager (release)..." -ForegroundColor Cyan
cargo build --release -p yeager
if ($LASTEXITCODE -ne 0) { throw "cargo build -p yeager failed" }
Write-Host "Building DNS recovery service (release)..." -ForegroundColor Cyan
cargo build --release -p dns-recovery
if ($LASTEXITCODE -ne 0) { throw "cargo build -p dns-recovery failed" }

$exe = Join-Path $PSScriptRoot "target\release\yeager.exe"
if (-not (Test-Path $exe)) {
    throw "Build did not produce $exe"
}
$helper = Join-Path $PSScriptRoot "target\release\yeager-dns-recovery.exe"
if (-not (Test-Path $helper)) {
    throw "Build did not produce $helper"
}

$dist = Join-Path $PSScriptRoot "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null
Copy-Item $exe (Join-Path $dist "yeager.exe") -Force
Copy-Item $helper (Join-Path $dist "yeager-dns-recovery.exe") -Force

$leviExe = Join-Path $PSScriptRoot "target\release\levi.exe"
if (Test-Path $leviExe) {
    Copy-Item $leviExe (Join-Path $dist "levi.exe") -Force
    $leviSize = [math]::Round((Get-Item $leviExe).Length / 1KB, 0)
    Write-Host "Done. dist\levi.exe ($leviSize KB)" -ForegroundColor Yellow
}

$size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
$helperSize = [math]::Round((Get-Item $helper).Length / 1KB, 0)
Write-Host "Done. dist\yeager.exe ($size MB), dist\yeager-dns-recovery.exe ($helperSize KB)" -ForegroundColor Green
