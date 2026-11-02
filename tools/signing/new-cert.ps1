<#
.SYNOPSIS
  Generates a dedicated self-signed code signing certificate (ECDSA P-256 + SHA-256).

.DESCRIPTION
  - Private key: Imported into CurrentUser\My as non-exportable, and exported to .signing\<Project>-codesign.pfx
    with a strong random password for CI use (.signing\ is git-ignored).
  - PFX password: 32 random bytes, saved with Windows DPAPI under %LOCALAPPDATA%\<Project>-signing, never exposed.
  - Public certificate: Exported to docs\signing\<Project>-codesign.cer (safe to commit to git).
  - Algorithm: ECDSA P-256 + SHA-256 with 2-year validity (standard Authenticode support on Win10/11).
#>
# SPDX-License-Identifier: MIT
param(
    [string]$ProjectName,
    [string]$Subject,
    [int]$Years = 2,
    [switch]$Force
)

. (Join-Path $PSScriptRoot 'common.ps1')

if ($ProjectName) {
    $script:ProjectName = $ProjectName
    $script:PublicCertPath = Join-Path $script:RepoRoot "docs\signing\$script:ProjectName-codesign.cer"
    $script:LocalPfxPath = Join-Path $script:SigningDir "$script:ProjectName-codesign.pfx"
    $script:PasswordPath = Join-Path $env:LOCALAPPDATA "$script:ProjectName-signing\pfx-password.clixml"
}

if (-not $Subject) {
    $Subject = "CN=$script:ProjectName, O=$env:USERNAME, C=VN"
}

if (((Test-Path $script:LocalPfxPath) -or (Test-Path $script:PublicCertPath)) -and -not $Force) {
    throw "A signing certificate already exists ($script:PublicCertPath). Use -Force only when intentionally rotating."
}

New-Item -ItemType Directory -Force -Path $script:SigningDir, (Split-Path $script:PublicCertPath), (Split-Path $script:PasswordPath) | Out-Null

Write-Host "Generating self-signed ECDSA code signing certificate for '$script:ProjectName'..."
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject `
    -KeyAlgorithm ECDSA_nistP256 -HashAlgorithm SHA256 -KeyUsage DigitalSignature `
    -KeyExportPolicy Exportable -CertStoreLocation Cert:\CurrentUser\My `
    -NotAfter (Get-Date).AddYears($Years)

# Generate 32-byte secure random password
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$password = ConvertTo-SecureString ([Convert]::ToBase64String($bytes)) -AsPlainText -Force
$password | Export-Clixml -Path $script:PasswordPath

# Export PFX and public CER
Export-PfxCertificate -Cert $cert -FilePath $script:LocalPfxPath -Password $password | Out-Null
Export-Certificate -Cert $cert -FilePath $script:PublicCertPath -Type CERT | Out-Null

# Re-import key as non-exportable into CurrentUser\My
$thumbprint = $cert.Thumbprint
Remove-Item -Path "Cert:\CurrentUser\My\$thumbprint" -DeleteKey
Import-PfxCertificate -FilePath $script:LocalPfxPath -CertStoreLocation Cert:\CurrentUser\My -Password $password | Out-Null

Write-Host "Code signing certificate created successfully!" -ForegroundColor Green
Write-Host "  Project     : $script:ProjectName"
Write-Host "  Subject     : $($cert.Subject)"
Write-Host "  Thumbprint  : $thumbprint"
Write-Host "  Valid until : $($cert.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host "  Public CER  : $script:PublicCertPath (commit to Git)"
Write-Host "  Private PFX : $script:LocalPfxPath (NEVER commit to Git)"
Write-Host "`nNext steps:"
Write-Host "  1. Run 'verify.ps1' to test pinning."
Write-Host "  2. Run 'trust-dev.ps1' if you want this development machine to trust the cert."
Write-Host "  3. Run 'ci-secrets.ps1' to prepare secrets for GitHub Actions CI."
