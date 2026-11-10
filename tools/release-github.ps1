<#
.SYNOPSIS
  Publishes a Yeager GitLab release on GitHub (iamcino/Yeager) with exactly the same files.

.DESCRIPTION
  Releases are built and signed once, on GitLab (tools\release-gitlab.ps1, by hand or from the
  GitLab release job). This script copies that release to GitHub so both sites ship
  byte-identical files:
    1. reads the GitLab release <tag> and downloads every file attached to it
    2. checks the files against SHA256SUMS.txt, and checks that yeager.exe, the installer and
       the yeager.exe inside the portable zip carry the pinned Yeager signature
       (docs\signing\Yeager-codesign.cer)
    3. creates the GitHub release <tag> with the same name, notes and files

  The GitHub workflow .github/workflows/release.yml runs it when a v* tag reaches GitHub
  (tools\sync-github.ps1 mirrors GitLab's master and tags). It can also be run by hand on a
  machine with gh signed in.

  Needs gh (GitHub CLI) with write access to the repository: GH_TOKEN in CI, or gh auth login.

.EXAMPLE
  .\tools\release-github.ps1 -Tag v1.1.5
#>
# SPDX-License-Identifier: MIT
param(
    [Parameter(Mandatory)][string]$Tag,
    [string]$GitLabProject = 'cino-group/yeager',
    [string]$GitLab = 'https://gitlab.com',
    [string]$GitHubRepo = $(if ($env:GITHUB_REPOSITORY) { $env:GITHUB_REPOSITORY } else { 'iamcino/Yeager' }),
    # how long to wait for the GitLab release to appear (the GitLab job may still be running)
    [int]$WaitMinutes = 0
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

function Step($text) { Write-Host "`n== $text" -ForegroundColor Cyan }
function Run($exe) {
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { & $exe @args } finally { $ErrorActionPreference = $old }
    if ($LASTEXITCODE -ne 0) { throw "$exe failed with exit code $LASTEXITCODE" }
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$api = "$GitLab/api/v4/projects/$([Uri]::EscapeDataString($GitLabProject))"
$env:CODESIGN_PROJECT_NAME = 'Yeager'
$verify = Join-Path $repo 'tools\signing\verify.ps1'
$thumb = (New-Object Security.Cryptography.X509Certificates.X509Certificate2 (Join-Path $repo 'docs\signing\Yeager-codesign.cer')).Thumbprint.ToUpperInvariant()

# ---------------------------------------------------------------- GitLab release
Step "Reading GitLab release $Tag"
$deadline = (Get-Date).AddMinutes($WaitMinutes)
while ($true) {
    try {
        # decode the bytes as UTF-8 ourselves: Windows PowerShell reads a JSON response without a
        # charset as Latin-1, which garbles the Vietnamese release notes
        $response = Invoke-WebRequest -UseBasicParsing "$api/releases/$([Uri]::EscapeDataString($Tag))"
        $release = [Text.Encoding]::UTF8.GetString($response.RawContentStream.ToArray()) | ConvertFrom-Json
        break
    }
    catch {
        if ((Get-Date) -ge $deadline) { throw "GitLab release $Tag not found: $($_.Exception.Message)" }
        Write-Host 'not there yet, waiting a minute'
        Start-Sleep -Seconds 60
    }
}
Write-Host "$($release.name), $(@($release.assets.links).Count) files"

$ErrorActionPreference = 'Continue'
& gh release view $Tag --repo $GitHubRepo *> $null
$ErrorActionPreference = 'Stop'
if ($LASTEXITCODE -eq 0) { throw "GitHub release $Tag already exists in $GitHubRepo." }
$global:LASTEXITCODE = 0

$out = Join-Path $repo "target\release-github\$Tag"
Remove-Item -Recurse -Force $out -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $out | Out-Null
foreach ($link in $release.assets.links) {
    if ($link.name -like 'levi*') { continue }
    $file = Join-Path $out $link.name
    for ($try = 1; ; $try++) {
        try { Invoke-WebRequest -UseBasicParsing $link.url -OutFile $file; break }
        catch {
            # gitlab.com rate-limits anonymous downloads; back off and retry
            if ($try -ge 5) { throw }
            Start-Sleep -Seconds (30 * $try)
        }
    }
    Write-Host "  $($link.name)"
}

# ---------------------------------------------------------------- checks
Step 'Checking the files'
$sumsFile = Join-Path $out 'SHA256SUMS.txt'
if (-not (Test-Path $sumsFile)) { throw 'SHA256SUMS.txt is missing from the GitLab release' }
foreach ($line in Get-Content $sumsFile) {
    if (-not $line.Trim()) { continue }
    $hash, $name = $line -split '\s+', 2
    $actual = (Get-FileHash (Join-Path $out $name) -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $hash.ToLower()) { throw "$name does not match SHA256SUMS.txt" }
    Write-Host "  $name OK"
}
$exe = Join-Path $out 'yeager.exe'
$setup = Get-ChildItem $out -Filter 'Yeager-Setup-*.exe' | Select-Object -First 1
$zip = Get-ChildItem $out -Filter 'Yeager-*-portable-x64.zip' | Select-Object -First 1
if (-not (Test-Path $exe) -or -not $setup -or -not $zip) { throw 'yeager.exe, the installer or the portable zip is missing' }
& $verify -Path $exe -ExpectedThumbprint $thumb -ProjectName Yeager
& $verify -Path $setup.FullName -ExpectedThumbprint $thumb -ProjectName Yeager
$check = Join-Path $repo "target\release-github\$Tag-zip"
Remove-Item -Recurse -Force $check -ErrorAction SilentlyContinue
Expand-Archive $zip.FullName $check -Force
foreach ($inner in Get-ChildItem $check -Recurse -Filter *.exe) {
    & $verify -Path $inner.FullName -ExpectedThumbprint $thumb -ProjectName Yeager
}
Remove-Item -Recurse -Force $check

# ---------------------------------------------------------------- GitHub release
Step "Creating GitHub release $Tag"
$notes = Join-Path $repo "target\release-github\$Tag-notes.md"
$text = "$($release.description)`n`nThe same files are published on GitLab: $GitLab/$GitLabProject/-/releases/$Tag`n"
[IO.File]::WriteAllText($notes, $text, (New-Object Text.UTF8Encoding $false))
$files = @(Get-ChildItem $out -File | ForEach-Object FullName)
Run gh release create $Tag @files --repo $GitHubRepo --verify-tag --title $release.name --notes-file $notes
Write-Host "Done: https://github.com/$GitHubRepo/releases/tag/$Tag"
