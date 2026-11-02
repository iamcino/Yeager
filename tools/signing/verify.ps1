<#
.SYNOPSIS
  Verifies the Authenticode signature, pinned thumbprint, and RFC 3161 timestamp of a binary.

.DESCRIPTION
  - Verifies binary signature status using Get-AuthenticodeSignature.
  - Enforces thumbprint pinning against docs\signing\<Project>-codesign.cer.
  - Requires presence of a valid RFC 3161 Timestamp.
  - Optional -JsonPath outputs structured metadata (signature.json) for release provenance.
#>
# SPDX-License-Identifier: MIT
param(
    [Parameter(Mandatory)][string]$Path,
    [string]$ExpectedThumbprint,
    [string]$JsonPath,
    [string]$ProjectName
)

. (Join-Path $PSScriptRoot 'common.ps1')

if ($ProjectName) {
    $script:ProjectName = $ProjectName
    $script:PublicCertPath = Join-Path $script:RepoRoot "docs\signing\$script:ProjectName-codesign.cer"
}

$Path = (Resolve-Path $Path).Path
$pinned = Get-PinnedThumbprint
if ($ExpectedThumbprint -and $ExpectedThumbprint.ToUpperInvariant() -ne $pinned) {
    throw "Expected thumbprint $ExpectedThumbprint does not match the pinned public certificate ($pinned)."
}

$sig = Get-AuthenticodeSignature -FilePath $Path

function Show-Diagnostic {
    $signerThumb = if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { '<none>' }
    $tsaSubject = if ($sig.TimeStamperCertificate) { $sig.TimeStamperCertificate.Subject } else { '<none>' }
    Write-Host "Authenticode Verification Diagnostic:" -ForegroundColor Red
    Write-Host "  File       : $Path" -ForegroundColor Red
    Write-Host "  Status     : $($sig.Status)" -ForegroundColor Red
    Write-Host "  Message    : $($sig.StatusMessage)" -ForegroundColor Red
    Write-Host "  Thumbprint : $signerThumb" -ForegroundColor Red
    Write-Host "  Timestamp  : $tsaSubject" -ForegroundColor Red
}

if ($sig.Status -in @('NotSigned', 'HashMismatch', 'NotSupportedFileFormat', 'Incompatible')) {
    Show-Diagnostic
    throw "Invalid signature on '${Path}': $($sig.Status) $($sig.StatusMessage)"
}
if (-not $sig.SignerCertificate) {
    Show-Diagnostic
    throw "No signer certificate found on $Path"
}

$thumbprint = $sig.SignerCertificate.Thumbprint.ToUpperInvariant()
if ($thumbprint -ne $pinned) {
    Show-Diagnostic
    throw "Signed by thumbprint $thumbprint, but expected pinned thumbprint $pinned"
}

# Authenticode verification policy:
# 1. Commercial CA certificates return Valid.
# 2. Self-signed certificates return UnknownError (WinVerifyTrust CERT_E_UNTRUSTEDROOT) or NotTrusted.
# Narrow exception: UnknownError is ONLY allowed if StatusMessage confirms an untrusted root certificate chain,
# and thumbprint strictly matches pinned cert and timestamp is verified. Any hash mismatch or unknown failure fails hard.
$isUntrustedRootChain = ($sig.Status -eq 'UnknownError' -and $sig.StatusMessage -like '*root certificate which is not trusted*')

if ($sig.Status -ne 'Valid' -and $sig.Status -ne 'NotTrusted' -and -not $isUntrustedRootChain) {
    Show-Diagnostic
    throw "Unexpected signature status on '${Path}': $($sig.Status) ($($sig.StatusMessage))"
}
if (-not $sig.TimeStamperCertificate) {
    Show-Diagnostic
    throw "$Path is signed but has NO timestamp authority attached!"
}

$cert = $sig.SignerCertificate
Write-Host "Authenticode Signature Verified: $Path" -ForegroundColor Green
Write-Host "  Signer     : $($cert.Subject)"
Write-Host "  Thumbprint : $thumbprint"
Write-Host "  Timestamp  : $($sig.TimeStamperCertificate.Subject)"
Write-Host "  Status     : $($sig.Status)"

if ($JsonPath) {
    $info = [ordered]@{
        file                = Split-Path $Path -Leaf
        sha256              = (Get-FileHash $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        signer              = $cert.Subject
        thumbprintSha1      = $thumbprint
        keyAlgorithm        = $cert.PublicKey.Oid.FriendlyName
        signatureAlgorithm  = $cert.SignatureAlgorithm.FriendlyName
        certificateNotAfter = $cert.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        selfSigned          = ($cert.Subject -eq $cert.Issuer)
        timestampAuthority  = $sig.TimeStamperCertificate.Subject
        status              = "$($sig.Status)"
        verifiedAt          = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    $jsonDir = Split-Path $JsonPath -Parent
    if ($jsonDir -and -not (Test-Path $jsonDir)) {
        New-Item -ItemType Directory -Force -Path $jsonDir | Out-Null
    }
    [IO.File]::WriteAllText($JsonPath, ($info | ConvertTo-Json -Depth 5) + "`n")
    Write-Host "  Report     : $JsonPath"
}
