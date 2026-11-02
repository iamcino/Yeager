# Shared helpers for Windows Authenticode signing scripts.
# Dot-source this file: . (Join-Path $PSScriptRoot 'common.ps1')
# SPDX-License-Identifier: MIT

$ErrorActionPreference = 'Stop'

function Get-RepoRoot {
    $dir = $PSScriptRoot
    while ($dir -and (Test-Path $dir)) {
        if (Test-Path (Join-Path $dir '.git')) { return $dir }
        $parent = Split-Path $dir -Parent
        if (-not $parent -or $parent -eq $dir) { break }
        $dir = $parent
    }
    return (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

$script:RepoRoot = Get-RepoRoot
$script:ProjectName = if ($env:CODESIGN_PROJECT_NAME) { 
    $env:CODESIGN_PROJECT_NAME 
} else { 
    Split-Path $script:RepoRoot -Leaf 
}

# Public certificate (committed to repository; thumbprint pins signatures)
$script:PublicCertPath = Join-Path $script:RepoRoot "docs\signing\$script:ProjectName-codesign.cer"

# Private materials (never committed; protected by .gitignore & CI checks)
$script:SigningDir = Join-Path $script:RepoRoot '.signing'
$script:LocalPfxPath = Join-Path $script:SigningDir "$script:ProjectName-codesign.pfx"

# PFX password protected by DPAPI for the current Windows user, outside the repo
$script:PasswordPath = Join-Path $env:LOCALAPPDATA "$script:ProjectName-signing\pfx-password.clixml"

# Default RFC 3161 Timestamp Authorities (TSA) with retry support
$script:DefaultTimestampUrls = @(
    'http://timestamp.digicert.com',
    'http://timestamp.sectigo.com'
)

function Get-SignTool {
    $roots = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'),
        (Join-Path $env:ProgramFiles 'Windows Kits\10\bin')
    )
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        $tool = Get-ChildItem -Path $root -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Directory.Name -eq 'x64' } |
            Sort-Object { [version]($_.Directory.Parent.Name -replace '[^0-9.]', '') } -Descending |
            Select-Object -First 1
        if ($tool) { return $tool.FullName }
    }
    throw 'signtool.exe not found. Please install the Windows 10/11 SDK or Visual Studio C++ build tools.'
}

function Get-PinnedThumbprint {
    if (-not (Test-Path $script:PublicCertPath)) {
        throw "Public certificate not found at '$script:PublicCertPath'. Run new-cert.ps1 first."
    }
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($script:PublicCertPath)
    return $cert.Thumbprint.ToUpperInvariant()
}
