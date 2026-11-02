<#
.SYNOPSIS
  Configures local developer machine trust for the project's code signing certificate.

.DESCRIPTION
  - Installs the public .cer into CurrentUser\Root and CurrentUser\TrustedPublisher.
  - Windows UAC prompt may appear for Root trust confirmation.
  - CAUTION: Only for development machines. Never install self-signed certificates on end-user machines.
  - Use -Remove to cleanly uninstall trust.
#>
# SPDX-License-Identifier: MIT
param(
    [switch]$Remove,
    [string]$ProjectName
)

. (Join-Path $PSScriptRoot 'common.ps1')

if ($ProjectName) {
    $script:ProjectName = $ProjectName
    $script:PublicCertPath = Join-Path $script:RepoRoot "docs\signing\$script:ProjectName-codesign.cer"
}

$thumbprint = Get-PinnedThumbprint
foreach ($store in 'Root', 'TrustedPublisher') {
    $location = "Cert:\CurrentUser\$store"
    if ($Remove) {
        if (Test-Path "$location\$thumbprint") {
            Remove-Item "$location\$thumbprint"
            Write-Host "Removed $thumbprint from CurrentUser\$store"
        }
    } else {
        Import-Certificate -FilePath $script:PublicCertPath -CertStoreLocation $location | Out-Null
        Write-Host "Trusted $thumbprint in CurrentUser\$store" -ForegroundColor Green
    }
}
