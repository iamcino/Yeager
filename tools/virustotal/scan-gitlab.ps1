<#
.SYNOPSIS
  Attaches a VirusTotal report to an already published GitLab release: downloads the
  published yeager.exe and the Yeager-Setup-<version>.exe installer, verifies both
  against the release SHA256SUMS.txt, scans them with tools\virustotal\scan.py (the
  same scanner the GitHub workflow runs) and uploads the report as the release asset
  virustotal-<tag>.json.

.DESCRIPTION
  Runs after the release job in the scan stage of .gitlab-ci.yml (allow_failure: the
  release is already published and is never touched by this script), or by hand to
  backfill an older release: pass -Version and provide GITLAB_TOKEN and VT_API_KEY.

  Failure is loud, never a quiet green: a missing VT_API_KEY, a missing Python 3,
  a release that does not exist, or an exe that does not match SHA256SUMS.txt all
  exit non-zero. Only the scan verdict itself is informational.

  GitLab access mirrors release-gitlab.ps1: GITLAB_TOKEN, the DPAPI token file,
  or the CI job token. VT_API_KEY is a protected, masked CI/CD variable holding the
  same VirusTotal key the GitHub workflow uses (owner decision, 2026-11-14).
#>
param(
    [string]$Version,
    [string]$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$Project = $(if ($env:CI_PROJECT_PATH) { $env:CI_PROJECT_PATH } else { 'cino-group/yeager' }),
    [string]$GitLab = $(if ($env:CI_SERVER_URL) { $env:CI_SERVER_URL } else { 'https://gitlab.com' })
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

function Step($text) { Write-Host "`n== $text" -ForegroundColor Cyan }

# ---------------------------------------------------------------- hard prerequisites
# Per the gated design these exit non-zero; the job is allow_failure, so the pipeline
# stays green, but the failure is visible instead of a report silently never appearing.
if (-not $env:VT_API_KEY) { throw 'VT_API_KEY is not set. Add it as a protected, masked CI/CD variable.' }
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { throw 'Python 3 was not found on PATH. Install Python 3 on the runner machine.' }

$projectId = [Uri]::EscapeDataString($Project)
$api = "$GitLab/api/v4/projects/$projectId"

# ---------------------------------------------------------------- token (as release-gitlab.ps1)
$token = $env:GITLAB_TOKEN
$tokenFile = Join-Path $env:LOCALAPPDATA 'Yeager-signing\gitlab-token.clixml'
if (-not $token -and (Test-Path $tokenFile)) {
    $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR((Import-Clixml $tokenFile)))
}
$headers = @{ 'PRIVATE-TOKEN' = $token }
if (-not $token -and $env:CI_JOB_TOKEN) {
    $headers = @{ 'JOB-TOKEN' = $env:CI_JOB_TOKEN }
} elseif (-not $token) {
    throw 'No GitLab token: set GITLAB_TOKEN or run inside GitLab CI (job token).'
}

# ---------------------------------------------------------------- version and release
if (-not $Version) {
    $cargo = Get-Content (Join-Path $Repo 'Cargo.toml') -Raw
    if ($cargo -notmatch '(?ms)^\[workspace\.package\].*?^version\s*=\s*"([^"]+)"') { throw 'No workspace version in Cargo.toml' }
    $Version = $Matches[1]
}
$Tag = "v$Version"
if ($env:CI_COMMIT_TAG -and $env:CI_COMMIT_TAG -ne $Tag) {
    throw "Tag $($env:CI_COMMIT_TAG) does not match version $Version"
}
$exeNames = @('yeager.exe', "Yeager-Setup-$Version.exe")
Step "VirusTotal report for GitLab release $Tag"
try {
    $release = Invoke-RestMethod -Headers $headers "$api/releases/$Tag"
} catch {
    throw "GitLab release $Tag could not be read ($($_.Exception.Message)). The scan stage only runs after a published release."
}
$sumsLink = $release.assets.links | Where-Object { $_.name -eq 'SHA256SUMS.txt' } | Select-Object -First 1
if (-not $sumsLink) { throw "Release $Tag lacks the SHA256SUMS.txt asset link." }
$exeLinks = @{}
foreach ($exeName in $exeNames) {
    $link = $release.assets.links | Where-Object { $_.name -eq $exeName } | Select-Object -First 1
    if (-not $link) { throw "Release $Tag lacks the $exeName asset link." }
    $exeLinks[$exeName] = $link
}

# ---------------------------------------------------------------- download and verify
$jobTag = $(if ($env:CI_JOB_ID) { $env:CI_JOB_ID } else { $PID })
$work = Join-Path $env:TEMP "yeager-vt-$jobTag"
$dl = Join-Path $work 'dl'
New-Item -ItemType Directory -Force $dl | Out-Null
try {
    foreach ($exeName in $exeNames) {
        Invoke-WebRequest -UseBasicParsing -Headers $headers -Uri $exeLinks[$exeName].url -OutFile (Join-Path $dl $exeName)
    }
    Invoke-WebRequest -UseBasicParsing -Headers $headers -Uri $sumsLink.url -OutFile (Join-Path $dl 'SHA256SUMS.txt')

    Step 'Verifying the published executables against SHA256SUMS.txt'
    $sums = @{}
    foreach ($line in Get-Content (Join-Path $dl 'SHA256SUMS.txt')) {
        $parts = $line.Trim() -split '\s+', 2
        if ($parts.Count -eq 2) { $sums[$parts[1].Trim('*')] = $parts[0] }
    }
    foreach ($exeName in $exeNames) {
        if (-not $sums.ContainsKey($exeName)) { throw "SHA256SUMS.txt has no $exeName line." }
        $actual = (Get-FileHash (Join-Path $dl $exeName) -Algorithm SHA256).Hash
        if ($actual.ToLower() -ne $sums[$exeName].ToLower()) { throw "$exeName hash $actual does not match SHA256SUMS.txt $($sums[$exeName])" }
        Write-Host "  $exeName OK ($($actual.ToLower()))"
    }

    # ------------------------------------------------------------ scan
    Step 'Scanning with VirusTotal'
    # The signing secrets ride along on protected refs; Python needs none of them.
    Remove-Item Env:CODESIGN_PFX_BASE64 -ErrorAction SilentlyContinue
    Remove-Item Env:CODESIGN_PFX_PASSWORD -ErrorAction SilentlyContinue
    $env:RELEASE_TAG = $Tag
    # scan.py globs dl/*.exe relative to the working directory and writes vt.json there
    Push-Location $work
    try {
        & $python.Source (Join-Path $Repo 'tools\virustotal\scan.py')
        if ($LASTEXITCODE -ne 0) { throw "scan.py failed with exit code $LASTEXITCODE (Python 3 must be a real install, not the Microsoft Store stub)." }
    } finally {
        Pop-Location
    }
    $report = Join-Path $work 'vt.json'
    if (-not (Test-Path $report)) { throw 'scan.py produced no vt.json.' }
    $parsed = Get-Content $report -Raw | ConvertFrom-Json
    if ($parsed.PSObject.Properties['status'] -and $parsed.status -eq 'skipped') {
        throw 'scan.py reported status skipped; refusing to treat that as success.'
    }

    # ------------------------------------------------------------ attach
    Step 'Attaching the report to the release'
    $name = "virustotal-$Tag.json"
    $named = Join-Path $work $name
    Copy-Item $report $named -Force
    $packageUrl = "$api/packages/generic/yeager/$Version/$name"
    # the generic package PUT does not overwrite: delete any earlier report first
    try { Invoke-RestMethod -Method Delete -Headers $headers $packageUrl | Out-Null } catch { }
    Invoke-RestMethod -Method Put -Headers $headers -InFile $named -Uri $packageUrl | Out-Null
    $links = Invoke-RestMethod -Headers $headers "$api/releases/$Tag/assets/links"
    foreach ($link in $links) {
        if ($link.name -eq $name) {
            Invoke-RestMethod -Method Delete -Headers $headers "$api/releases/$Tag/assets/links/$($link.id)" | Out-Null
        }
    }
    $linkBody = @{ name = $name; url = $packageUrl; direct_asset_path = "/$name"; link_type = 'other' } | ConvertTo-Json
    Invoke-RestMethod -Method Post -Headers $headers -Uri "$api/releases/$Tag/assets/links" `
        -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($linkBody)) | Out-Null
    Write-Host "Attached $name to release $Tag"
    foreach ($exeName in $exeNames) {
        $entry = $parsed.results.PSObject.Properties[$exeName]
        if ($entry) { Write-Host "VirusTotal: $exeName $($entry.Value.link) ($($entry.Value.status))" }
    }
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
