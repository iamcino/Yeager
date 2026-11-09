<#
.SYNOPSIS
  Builds, signs and publishes a Yeager release on GitLab with the same files the GitHub
  release workflow ships: the signed installer, the portable zip, the signed yeager.exe the
  in-app updater downloads, SHA256SUMS.txt, the signature JSON files, the public certificate,
  LICENSE, THIRD-PARTY-NOTICES.md and release notes from both changelogs (English first).
  levi.exe is never shipped.

.DESCRIPTION
  Run it on Windows with the Rust toolchain, Inno Setup 6 or 7 and the Windows SDK (signtool).
  For the GNU Rust toolchain, put w64devkit on PATH first (the script adds C:\Soft\w64devkit\bin
  when it exists). The release is built from a clean temporary worktree of -Ref, so your own
  checkout is not touched. The version is the workspace version in Cargo.toml; the tag is
  v<version>.

  Signing, first match wins:
    1. the pinned Yeager certificate in Cert:\CurrentUser\My
    2. -PfxPath, or <repo>\.signing\Yeager-codesign.pfx, with the password from
       CODESIGN_PFX_PASSWORD or %LOCALAPPDATA%\Yeager-signing\pfx-password.clixml (DPAPI),
       or asked for when the script runs

  GitLab access: a project access token (scope: api) read from GITLAB_TOKEN, from
  %LOCALAPPDATA%\Yeager-signing\gitlab-token.clixml (DPAPI-protected, see below), the CI job
  token inside GitLab CI, or asked for when the script starts. The script never writes it anywhere.

  Same files on both sites: after the GitHub workflow has published a release, -FromGitHub
  downloads that release's files and publishes exactly those on GitLab instead of building again
  (set GITHUB_TOKEN when the GitHub repository is private). -AssetsDir does the same from a folder
  you already have. Either way yeager.exe and the installer must carry the pinned signature and
  match SHA256SUMS.txt.

.EXAMPLE
  .\tools\release-gitlab.ps1 -FromGitHub          # mirror the GitHub release of master's version
.EXAMPLE
  .\tools\release-gitlab.ps1 -Ref v1.1.3 -AssetsDir D:\Downloads\yeager-1.1.3
.EXAMPLE
  .\tools\release-gitlab.ps1 -Ref v1.2.0          # build, sign and publish here
.EXAMPLE
  .\tools\release-gitlab.ps1 -Ref master -DryRun  # build and sign only; nothing is uploaded
#>
# SPDX-License-Identifier: MIT
param(
    [string]$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [string]$Ref = 'master',
    [string]$Project = $(if ($env:CI_PROJECT_PATH) { $env:CI_PROJECT_PATH } else { 'cino-group/yeager' }),
    [string]$GitLab = $(if ($env:CI_SERVER_URL) { $env:CI_SERVER_URL } else { 'https://gitlab.com' }),
    [string]$GitHubRepo = 'iamcino/Yeager',
    [string]$PfxPath,
    [switch]$FromGitHub,
    [string]$AssetsDir,
    [switch]$SkipTests,
    [switch]$Prerelease,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

function Step($text) { Write-Host "`n== $text" -ForegroundColor Cyan }
function Quiet { $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'; try { & $args[0] @($args | Select-Object -Skip 1) 2>&1 | Out-Null } finally { $ErrorActionPreference = $old } }
function Run($exe) {
    & $exe @args
    if ($LASTEXITCODE -ne 0) { throw "$exe failed with exit code $LASTEXITCODE" }
}
function Unprotect($secure) {
    [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}

# the signing helpers name files after the project, not after the folder they run in
$env:CODESIGN_PROJECT_NAME = 'Yeager'
$secretsDir = Join-Path $env:LOCALAPPDATA 'Yeager-signing'
$projectId = [Uri]::EscapeDataString($Project)
$api = "$GitLab/api/v4/projects/$projectId"

# ---------------------------------------------------------------- token
$token = $env:GITLAB_TOKEN
# saved once with: Read-Host -AsSecureString | Export-Clixml "$env:LOCALAPPDATA\Yeager-signing\gitlab-token.clixml"
# (DPAPI: only this Windows user on this machine can read it)
$tokenFile = Join-Path $secretsDir 'gitlab-token.clixml'
if (-not $token -and (Test-Path $tokenFile)) { $token = Unprotect (Import-Clixml $tokenFile) }
$headers = @{ 'PRIVATE-TOKEN' = $token }
if (-not $token -and $env:CI_JOB_TOKEN) {
    # inside GitLab CI the job token can upload packages and create the release
    $headers = @{ 'JOB-TOKEN' = $env:CI_JOB_TOKEN }
} elseif (-not $token -and -not $DryRun) {
    $token = Unprotect (Read-Host 'GitLab access token (scope: api)' -AsSecureString)
    $headers = @{ 'PRIVATE-TOKEN' = $token }
}

# ---------------------------------------------------------------- worktree
Step "Preparing a clean copy of $Ref"
$commit = (git -C $Repo rev-parse --verify "$Ref^{commit}").Trim()
if ($LASTEXITCODE -ne 0) { throw "Unknown ref $Ref" }
# inside the repo's ignored target folder, not %TEMP%: antivirus blocks reading the WinDivert
# driver that levi embeds, and locks fresh build scripts, when they sit in %TEMP%
$work = Join-Path $Repo "target\release-gitlab\src-$($commit.Substring(0, 8))"
if (Test-Path $work) {
    Quiet git -C $Repo worktree remove --force $work
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
Run git -C $Repo worktree add --detach $work $commit

try {
    Set-Location $work
    $cargo = Get-Content Cargo.toml -Raw
    if ($cargo -notmatch '(?ms)^\[workspace\.package\].*?^version\s*=\s*"([^"]+)"') { throw 'No workspace version in Cargo.toml' }
    $version = $Matches[1]
    $tag = "v$version"
    Write-Host "Version $version, tag $tag, commit $commit"
    if ($env:CI_COMMIT_TAG -and $env:CI_COMMIT_TAG -ne $tag) {
        throw "Tag $($env:CI_COMMIT_TAG) does not match the Cargo.toml version $version"
    }
    if ($version.Contains('-') -and -not $Prerelease) {
        # GitLab has no pre-release flag: the newest release becomes "latest" for every download link
        throw "$version is a pre-release. Pass -Prerelease if it really should become the latest GitLab release."
    }

    if (-not $DryRun) {
        $exists = $true
        try { Invoke-RestMethod -Headers $headers "$api/releases/$tag" | Out-Null }
        catch { $exists = $false }
        if ($exists) { throw "GitLab release $tag already exists. Delete it first or raise the version." }
    }

    $out = Join-Path $work 'release-out'
    New-Item -ItemType Directory -Force $out | Out-Null
    $setup = "Yeager-Setup-$version.exe"
    $zip = "Yeager-$version-portable-x64.zip"

    if ($FromGitHub -or $AssetsDir) {
        if ($FromGitHub) {
            Step "Downloading GitHub release $tag"
            $ghHeaders = @{ 'User-Agent' = 'yeager-release' }
            if ($env:GITHUB_TOKEN) { $ghHeaders['Authorization'] = "Bearer $($env:GITHUB_TOKEN)" }
            $gh = Invoke-RestMethod -Headers $ghHeaders "https://api.github.com/repos/$GitHubRepo/releases/tags/$tag"
            foreach ($asset in $gh.assets) {
                if ($asset.name -like 'levi*') { continue }
                # the API URL works for private repositories too; it redirects to the file
                Invoke-WebRequest -UseBasicParsing -Headers ($ghHeaders + @{ 'Accept' = 'application/octet-stream' }) `
                    -Uri $asset.url -OutFile (Join-Path $out $asset.name)
                Write-Host "  $($asset.name)"
            }
        } else {
            Get-ChildItem $AssetsDir -File | Where-Object Name -notlike 'levi*' | Copy-Item -Destination $out
        }
        Step 'Checking the files'
        foreach ($f in @('yeager.exe', $setup, $zip, 'SHA256SUMS.txt')) {
            if (-not (Test-Path (Join-Path $out $f))) { throw "$f is missing from the release files" }
        }
        & .\tools\signing\verify.ps1 -Path (Join-Path $out 'yeager.exe')
        & .\tools\signing\verify.ps1 -Path (Join-Path $out $setup)
        $sums = @()
        foreach ($line in Get-Content (Join-Path $out 'SHA256SUMS.txt')) {
            if (-not $line.Trim()) { continue }
            $hash, $name = $line -split '\s+', 2
            if ($name -like 'levi*') { continue }
            $actual = (Get-FileHash (Join-Path $out $name) -Algorithm SHA256).Hash.ToLower()
            if ($actual -ne $hash.ToLower()) { throw "$name does not match SHA256SUMS.txt" }
            Write-Host "  $name OK"
            $sums += $line
        }
        # same list without levi.exe, which Yeager never ships
        [IO.File]::WriteAllText("$out\SHA256SUMS.txt", ($sums -join "`n") + "`n")
    } else {
        $devkit = 'C:\Soft\w64devkit\bin'
        if ((Test-Path $devkit) -and ($env:Path -notlike "*$devkit*")) { $env:Path = "$devkit;$env:Path" }

        # ------------------------------------------------------------ test and build
        # a kept target folder makes the next release build fast
        $env:CARGO_TARGET_DIR = Join-Path $Repo 'target\release-gitlab'
        if (-not $SkipTests) {
            Step 'Testing'
            Run cargo test --locked --workspace --exclude levi
        }
        Step 'Building yeager.exe (release)'
        $built = $false
        foreach ($try in 1..3) {
            & cargo build --locked --release -p yeager
            if ($LASTEXITCODE -eq 0) { $built = $true; break }
            Write-Host "cargo build failed (try $try of 3), retrying" -ForegroundColor Yellow
        }
        if (-not $built) { throw 'cargo build failed' }
        $dist = Join-Path $work 'dist'
        New-Item -ItemType Directory -Force $dist | Out-Null
        Copy-Item (Join-Path $env:CARGO_TARGET_DIR 'release\yeager.exe') $dist

        # ------------------------------------------------------------ sign
        . .\tools\signing\common.ps1
        $pinned = Get-PinnedThumbprint
        $signArgs = @{}
        if (-not (Test-Path "Cert:\CurrentUser\My\$pinned")) {
            $localPfx = Join-Path $Repo '.signing\Yeager-codesign.pfx'
            if (-not $PfxPath -and (Test-Path $localPfx)) { $PfxPath = $localPfx }
            if (-not $PfxPath) { throw "No signing key: certificate $pinned is not in CurrentUser\My and no PFX was given (-PfxPath)." }
            if (-not $env:CODESIGN_PFX_PASSWORD) {
                $pwFile = Join-Path $secretsDir 'pfx-password.clixml'
                $securePw = if (Test-Path $pwFile) { Import-Clixml $pwFile } else { Read-Host 'PFX password' -AsSecureString }
                $env:CODESIGN_PFX_PASSWORD = Unprotect $securePw
            }
            $signArgs = @{ PfxPath = $PfxPath }
            Write-Host "Signing with $PfxPath"
        } else {
            Write-Host 'Signing with the certificate in CurrentUser\My'
        }
        function Sign($file, $json) {
            & .\tools\signing\sign.ps1 -Path $file @signArgs
            # absolute path: .NET file calls use the process directory, not PowerShell's location
            & .\tools\signing\verify.ps1 -Path $file -JsonPath (Join-Path $out $json)
        }

        try {
            Step 'Signing yeager.exe'
            Sign "$dist\yeager.exe" 'yeager-signature.json'

            # -------------------------------------------------------- installer
            Step 'Building the installer'
            $iscc = (Get-Command iscc -ErrorAction SilentlyContinue | Select-Object -First 1).Source
            if (-not $iscc) {
                $iscc = Get-ChildItem "${env:ProgramFiles(x86)}\Inno Setup*\ISCC.exe", "$env:ProgramFiles\Inno Setup*\ISCC.exe",
                          "$env:LOCALAPPDATA\Programs\Inno Setup*\ISCC.exe", 'C:\Soft\Inno Setup*\ISCC.exe' -ErrorAction SilentlyContinue |
                    Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
            }
            if (-not $iscc) { throw 'Inno Setup not found. Run "winget install JRSoftware.InnoSetup" and try again.' }
            $numeric = ($version -replace '-.*$', '') + '.0'
            Run $iscc /Q installer\setup.iss "/DAppVersion=$version" "/DNumericVersion=$numeric"
            Step 'Signing the installer'
            Sign "$dist\$setup" "Yeager-Setup-$version-signature.json"
        } finally {
            Remove-Item Env:\CODESIGN_PFX_PASSWORD -ErrorAction SilentlyContinue
        }

        # ------------------------------------------------------------ package
        Step 'Packaging'
        $stage = Join-Path $dist 'Yeager-portable'
        New-Item -ItemType Directory -Force $stage | Out-Null
        Copy-Item "$dist\yeager.exe", LICENSE, THIRD-PARTY-NOTICES.md $stage
        if (Test-Path licenses) { Copy-Item licenses $stage -Recurse }
        Compress-Archive -Path "$stage\*" -DestinationPath (Join-Path $out $zip) -Force
        Copy-Item "$dist\yeager.exe", "$dist\$setup" $out
        Copy-Item docs\signing\Yeager-codesign.cer, LICENSE, THIRD-PARTY-NOTICES.md $out
        # yeager.exe on its own is what the in-app updater downloads; it checks it against this list
        $lines = foreach ($f in @($setup, $zip, 'yeager.exe')) {
            "$((Get-FileHash (Join-Path $out $f) -Algorithm SHA256).Hash.ToLower())  $f"
        }
        [IO.File]::WriteAllText("$out\SHA256SUMS.txt", ($lines -join "`n") + "`n")
        $lines | ForEach-Object { Write-Host "  $_" }
    }

    # ------------------------------------------------------------ notes
    function Get-Section($file) {
        # a tag cut before its changelog entry was written (v1.1.3) has no section for itself:
        # fall back to the changelog of the checkout running this script
        foreach ($path in @((Join-Path $work $file), (Join-Path $Repo $file))) {
            $section = @(); $found = $false
            foreach ($line in Get-Content $path -Encoding utf8) {
                if ($line.StartsWith('## ')) {
                    if ($found) { break }
                    $found = $line -match "^## \[?$([regex]::Escape($version))\]?(\s|$)"
                } elseif ($found) { $section += $line }
            }
            if ($found) { return ($section -join "`n").Trim() }
        }
        throw "$file has no section for $version"
    }
    $blob = "$GitLab/$Project/-/blob/master"
    $notes = (Get-Section CHANGELOG.md) + "`n`n## Tiếng Việt`n`n" + (Get-Section CHANGELOG.vi.md) +
        "`n`n---`n`nRun ``$setup`` to install, or unzip the portable build and run ``yeager.exe`` as administrator. " +
        "Requires Windows 11 or Windows Server 2022, x64.`n`n[Changelog]($blob/CHANGELOG.md) · [Nhật ký thay đổi]($blob/CHANGELOG.vi.md)`n"
    [IO.File]::WriteAllText("$out\release-notes.md", $notes, (New-Object Text.UTF8Encoding $false))

    $files = @(Get-ChildItem $out -File | Where-Object { $_.Name -ne 'release-notes.md' -and $_.Name -notlike 'levi*' } | ForEach-Object Name)
    if ($DryRun) {
        Step "Dry run: nothing uploaded. Files are in $out"
        $files | ForEach-Object { Write-Host "  $_" }
        # keep the files: move them out of the worktree before it is removed
        $keep = Join-Path $Repo "target\release-gitlab\out-$version"
        Remove-Item -Recurse -Force $keep -ErrorAction SilentlyContinue
        Move-Item $out $keep
        Write-Host "Kept in $keep"
        return
    }

    # ------------------------------------------------------------ upload
    Step 'Uploading to the GitLab package registry'
    # stable paths, so .../-/releases/permalink/latest/downloads/<path> always gets the newest file
    $stable = @{ $setup = 'Yeager-Setup.exe'; $zip = 'Yeager-portable-x64.zip' }
    $links = @()
    foreach ($f in $files) {
        $url = "$api/packages/generic/yeager/$version/$f"
        Invoke-RestMethod -Method Put -Headers $headers -InFile (Join-Path $out $f) -Uri $url | Out-Null
        Write-Host "  $f"
        $path = if ($stable.ContainsKey($f)) { $stable[$f] } else { $f }
        $links += @{ name = $f; url = $url; direct_asset_path = "/$path"; link_type = $(if ($f -like '*.exe' -or $f -like '*.zip') { 'package' } else { 'other' }) }
    }

    Step "Creating release $tag"
    $body = @{
        name = "Yeager $version"
        tag_name = $tag
        ref = $commit
        description = $notes
        assets = @{ links = $links }
    } | ConvertTo-Json -Depth 5
    Invoke-RestMethod -Method Post -Headers $headers -Uri "$api/releases" `
        -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body)) | Out-Null
    Write-Host "Done: $GitLab/$Project/-/releases/$tag"
    Write-Host "Latest installer: $GitLab/$Project/-/releases/permalink/latest/downloads/Yeager-Setup.exe"
}
finally {
    Set-Location $Repo
    Quiet git -C $Repo worktree remove --force $work
}
