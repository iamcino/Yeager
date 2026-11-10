<#
.SYNOPSIS
  Makes github.com/iamcino/Yeager an exact mirror of gitlab.com/cino-group/yeager: same master,
  same v* tags.

.DESCRIPTION
  GitLab is where Yeager is developed, tested (GitLab CI on the Garen-PC runner) and released
  (tools\release-gitlab.ps1). GitHub carries the same commits and tags, never anything else:
    1. fetches GitLab master and its tags
    2. pushes GitLab master to GitHub master, never forced, so GitHub master must already be an
       ancestor of GitLab master
    3. pushes every v* tag GitLab has that GitHub lacks

  A new v* tag on GitHub starts .github/workflows/release.yml, which publishes the GitLab
  release on GitHub with the same files (tools\release-github.ps1). Run this script after each
  merge to GitLab master and after each GitLab release.

  Remotes: -GitLab (default 'gl') must point at GitLab, -GitHub (default 'origin') at GitHub.

.EXAMPLE
  .\tools\sync-github.ps1           # show what would be pushed
  .\tools\sync-github.ps1 -Push     # push it
#>
# SPDX-License-Identifier: MIT
param(
    [string]$GitLab = 'gl',
    [string]$GitHub = 'origin',
    [switch]$Push
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

function Step($text) { Write-Host "`n== $text" -ForegroundColor Cyan }
# git reports progress on stderr (push does even on success); judge by the exit code
function RunGit {
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $out = & git.exe -C $repo @args 2>&1 } finally { $ErrorActionPreference = $old }
    if ($LASTEXITCODE -ne 0) { throw "git $($args -join ' ') failed:`n$($out -join "`n")" }
    $out | Where-Object { $_ -is [string] }
}

Step "Fetching $GitLab and $GitHub"
RunGit fetch --prune --tags $GitLab | Out-Null
RunGit fetch --prune $GitHub | Out-Null

$lab = (RunGit rev-parse "$GitLab/master").Trim()
$hub = (RunGit rev-parse "$GitHub/master").Trim()
Write-Host "GitLab master $($lab.Substring(0, 8)), GitHub master $($hub.Substring(0, 8))"
$old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
& git.exe -C $repo merge-base --is-ancestor $hub $lab
$ancestor = $LASTEXITCODE -eq 0
$ErrorActionPreference = $old
if (-not $ancestor) {
    throw "GitHub master has commits GitLab master lacks. Merge them on GitLab first; this script never forces a push."
}

$labTags = @{}
foreach ($line in RunGit ls-remote --tags $GitLab 'refs/tags/v*') {
    $sha, $ref = $line -split '\s+'
    if ($ref -notlike '*^{}') { $labTags[$ref] = $sha }
}
$hubTags = @{}
foreach ($line in RunGit ls-remote --tags $GitHub 'refs/tags/v*') {
    $sha, $ref = $line -split '\s+'
    if ($ref -notlike '*^{}') { $hubTags[$ref] = $sha }
}
$missing = @($labTags.Keys | Where-Object { -not $hubTags.ContainsKey($_) } | Sort-Object { [version](($_ -replace '^refs/tags/v', '') -replace '-.*$', '') })
$different = @($labTags.Keys | Where-Object { $hubTags.ContainsKey($_) -and $hubTags[$_] -ne $labTags[$_] })
if ($different) { throw "These tags point elsewhere on GitHub; fix them by hand: $($different -join ', ')" }

Step 'Plan'
Write-Host ($(if ($lab -eq $hub) { 'master is already the same' } else { "master: $($hub.Substring(0, 8)) -> $($lab.Substring(0, 8))" }))
Write-Host ($(if ($missing) { "tags to push: $(($missing | ForEach-Object { $_ -replace '^refs/tags/', '' }) -join ', ')" } else { 'no new tags' }))
$extra = @($hubTags.Keys | Where-Object { -not $labTags.ContainsKey($_) })
if ($extra) { Write-Host "only on GitHub (left alone): $(($extra | ForEach-Object { $_ -replace '^refs/tags/', '' }) -join ', ')" -ForegroundColor Yellow }

if (-not $Push) { Write-Host "`nNothing pushed. Run again with -Push."; return }

if ($lab -ne $hub) {
    Step 'Pushing master'
    RunGit push $GitHub "$($lab):refs/heads/master" | Out-Null
}
# one tag per push, oldest first, so each one starts its own release workflow run in order
foreach ($ref in $missing) {
    Step "Pushing $($ref -replace '^refs/tags/', '')"
    RunGit push $GitHub "$($ref):$ref" | Out-Null
}
Write-Host "`nGitHub mirrors GitLab master at $($lab.Substring(0, 8))."
