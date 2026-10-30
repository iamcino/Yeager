# Yeager — build release binary and assemble dist\
# Requires: Rust toolchain plus a resource compiler for the embedded
# icon/manifest: `windres` (w64devkit/MSYS2) for the GNU toolchain, or the
# Windows SDK `rc.exe` for MSVC. If Explorer still shows an old icon after a
# rebuild, refresh its icon cache with `ie4uinit.exe -show`.

$ErrorActionPreference = "Stop"

Write-Host "Building Yeager (release)..." -ForegroundColor Cyan
cargo build --release

$exe = Join-Path $PSScriptRoot "target\release\yeager.exe"
if (-not (Test-Path $exe)) {
    throw "Build did not produce $exe"
}

$dist = Join-Path $PSScriptRoot "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null
Copy-Item $exe (Join-Path $dist "yeager.exe") -Force

$size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Host "Done. dist\yeager.exe ($size MB)" -ForegroundColor Green
