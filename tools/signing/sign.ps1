<#
.SYNOPSIS
  Signs a Windows executable/installer with RFC 3161 timestamping and retry logic.

.DESCRIPTION
  - Local mode : Automatically uses the pinned certificate in Cert:\CurrentUser\My.
  - CI mode    : Supply -PfxPath and set environment variable CODESIGN_PFX_PASSWORD.
  - Robustness : Tries each timestamp server up to 3 times before falling back to the next server.
  - Verification: Automatically invokes verify.ps1 after signing to guarantee valid signature.
#>
# SPDX-License-Identifier: MIT
param(
    [Parameter(Mandatory)][string]$Path,
    [string]$PfxPath,
    [string]$ExpectedThumbprint,
    [string[]]$TimestampUrl,
    [string]$ProjectName
)

. (Join-Path $PSScriptRoot 'common.ps1')

if ($ProjectName) {
    $script:ProjectName = $ProjectName
    $script:PublicCertPath = Join-Path $script:RepoRoot "docs\signing\$script:ProjectName-codesign.cer"
    $script:LocalPfxPath = Join-Path $script:SigningDir "$script:ProjectName-codesign.pfx"
}

$Path = (Resolve-Path $Path).Path
$pinned = Get-PinnedThumbprint
if ($ExpectedThumbprint -and $ExpectedThumbprint.ToUpperInvariant() -ne $pinned) {
    throw "Expected thumbprint $ExpectedThumbprint does not match the pinned public certificate ($pinned)."
}

$urls = @($TimestampUrl | Where-Object { $_ })
if ($urls.Count -eq 0) { $urls = $script:DefaultTimestampUrls }
foreach ($url in $urls) {
    if ($url -match 'example\.(com|org|net)') {
        throw "Refusing placeholder domain as timestamp server: $url"
    }
}

$signtool = Get-SignTool

# Determine signing arguments
if ($PfxPath) {
    $altEnvVar = "$($script:ProjectName.ToUpper())_SIGN_PFX_PASSWORD"
    $altVal = [Environment]::GetEnvironmentVariable($altEnvVar)
    $pwdEnv = if ($env:CODESIGN_PFX_PASSWORD) { 
        $env:CODESIGN_PFX_PASSWORD 
    } elseif ($altVal) {
        $altVal
    } else {
        throw "Environment variable CODESIGN_PFX_PASSWORD is not set."
    }
    
    $pfxCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($PfxPath, $pwdEnv)
    if ($pfxCert.Thumbprint.ToUpperInvariant() -ne $pinned) {
        throw "PFX thumbprint ($($pfxCert.Thumbprint)) does not match pinned certificate ($pinned)."
    }
    $certArgs = @('/f', $PfxPath, '/p', $pwdEnv)
} else {
    if (-not (Test-Path "Cert:\CurrentUser\My\$pinned")) {
        throw "Pinned certificate $pinned not found in Cert:\CurrentUser\My. Run new-cert.ps1 first."
    }
    $certArgs = @('/sha1', $pinned, '/s', 'My')
}

$signed = $false
foreach ($url in $urls) {
    for ($attempt = 1; $attempt -le 3 -and -not $signed; $attempt++) {
        Write-Host "Signing '$Path' with TSA '$url' (attempt $attempt/3)..."
        & $signtool sign /fd sha256 /tr $url /td sha256 @certArgs $Path | Out-Host
        if ($LASTEXITCODE -eq 0) {
            $signed = $true
            Write-Host "Successfully signed and timestamped by $url" -ForegroundColor Green
        } else {
            Write-Warning "Signing with $url failed (attempt $attempt/3). Retrying..."
            Start-Sleep -Seconds (2 * $attempt)
        }
    }
    if ($signed) { break }
}

$global:LASTEXITCODE = 0
if (-not $signed) {
    throw "Signing failed on all timestamp authorities. An untimestamped binary must not be released."
}

# Automatically verify after signing
& (Join-Path $PSScriptRoot 'verify.ps1') -Path $Path -ExpectedThumbprint $pinned
