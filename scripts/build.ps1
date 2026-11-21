#Requires -Version 5.1
<#
.SYNOPSIS
  Build (and optionally package/sign) WSecret Quick Access for x64 and/or ARM64.

.DESCRIPTION
  Builds the Rust broker (crates/wsecret-broker) for the requested MSVC target(s), then
  builds the WinUI 3 app (src/WSecret/WSecret.csproj) with the broker executable wired in
  via -p:WSecretBrokerExe. -Package additionally produces a signed MSIX using the
  single-project MSIX packaging targets; a self-signed code-signing certificate with
  subject exactly "CN=WSecret" is provisioned to CurrentUser\My when none is supplied.

  This script performs builds only. It claims no test or runtime evidence.

.EXAMPLE
  .\scripts\build.ps1 -Arch x64 -Configuration Release -Package
.EXAMPLE
  .\scripts\build.ps1 -Arch both -Configuration Release -CertThumbprint <thumb>
#>
[CmdletBinding()]
param(
    [ValidateSet('x64', 'arm64', 'both')]
    [string]$Arch = 'x64',

    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    # Also produce the signed MSIX package.
    [switch]$Package,

    # Signing identity: thumbprint from CurrentUser\My, or a PFX file + password.
    [string]$CertThumbprint = '',
    [string]$CertFile = '',
    [string]$CertPassword = '',

    # Override the broker executable copied into the package.
    [string]$BrokerExe = '',

    [switch]$SkipBroker,
    [switch]$SkipApp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$AppProject = Join-Path $RepoRoot 'src\WSecret\WSecret.csproj'
$DistDir = Join-Path $RepoRoot 'dist'

function Invoke-Checked {
    param([string]$FilePath, [string[]]$Arguments, [string]$Label)
    Write-Host ">> $Label" -ForegroundColor Cyan
    Write-Host ">> $FilePath $($Arguments -join ' ')"
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

function Get-PinnedDotNetVersion {
    $globalJson = Join-Path $RepoRoot 'global.json'
    if (-not (Test-Path $globalJson)) { return $null }
    $json = Get-Content $GlobalJson -Raw | ConvertFrom-Json
    return $json.sdk.version
}

function Get-CodeSigningCert {
    param([string]$Thumbprint)

    if ($Thumbprint) {
        $cert = Get-Item "Cert:\CurrentUser\My\$Thumbprint" -ErrorAction SilentlyContinue
        if (-not $cert) { throw "Certificate $Thumbprint not found in CurrentUser\My" }
        return $cert
    }

    $codeSignOid = '1.3.6.1.5.5.7.3.3'
    $existing = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object {
            $_.Subject -eq 'CN=WSecret' -and
            $_.NotAfter -gt (Get-Date).AddDays(30) -and
            ($_.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq $codeSignOid })
        } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1
    if ($existing) { return $existing }

    Write-Host '>> Provisioning self-signed code-signing certificate CN=WSecret (CurrentUser\My)'
    $cert = New-SelfSignedCertificate `
        -Subject 'CN=WSecret' `
        -Type CodeSigningCert `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyAlgorithm RSA -KeyLength 2048 `
        -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddYears(2)

    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
    $cerPath = Join-Path $DistDir 'wsecret-dev.cer'
    Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
    Write-Host ">> Exported public certificate to $cerPath"
    Write-Host '>> To install the package locally, trust it first (development only):' -ForegroundColor Yellow
    Write-Host ">>   Import-Certificate -FilePath '$cerPath' -CertStoreLocation Cert:\CurrentUser\Root"
    return $cert
}

# --- Preconditions -------------------------------------------------------------

$archList = if ($Arch -eq 'both') { @('x64', 'arm64') } else { @($Arch) }

if (-not $SkipApp) {
    if (-not (Test-Path $AppProject)) { throw "App project not found: $AppProject" }
}

$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
if (-not $dotnet) { throw 'dotnet SDK not found on PATH (.NET SDK 11.0.100 is pinned by global.json)' }
$pinned = Get-PinnedDotNetVersion
Push-Location $RepoRoot
try {
    $actual = (& dotnet --version).Trim()
} finally {
    Pop-Location
}
if ($pinned -and $actual -ne $pinned) {
    throw "dotnet SDK $actual active, but global.json pins $pinned. Install the pinned SDK."
}

if (-not $SkipBroker) {
    $rustc = Get-Command rustc -ErrorAction SilentlyContinue
    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    if (-not $rustc -or -not $cargo) { throw 'rustc/cargo not found on PATH (Rust 1.100.0 is pinned by rust-toolchain.toml)' }
    $rustv = (& rustc --version)
    if ($rustv -notmatch '1\.100\.0') {
        Write-Warning "rustc reports '$rustv'; rust-toolchain.toml pins 1.100.0 (rustup selects it automatically)."
    }
}

# --- Broker -------------------------------------------------------------------

$brokerByArch = @{}
foreach ($a in $archList) {
    $triple = if ($a -eq 'arm64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
    $cfgDir = $Configuration.ToLowerInvariant()
    $outExe = Join-Path $RepoRoot "target\$triple\$cfgDir\wsecret-broker.exe"

    if (-not $SkipBroker) {
        $cargoArgs = @('build', '-p', 'wsecret-broker', '--locked', '--target', $triple)
        if ($Configuration -eq 'Release') { $cargoArgs += '--release' }
        Invoke-Checked -FilePath 'cargo' -Arguments $cargoArgs -Label "broker ($triple, $Configuration)"
        if (-not (Test-Path $outExe)) { throw "Broker build did not produce $outExe" }
    }
    $brokerByArch[$a] = $outExe
}

# --- App (and packaging) ------------------------------------------------------

if (-not $SkipApp) {
    $certProps = @()
    if ($Package) {
        if ($CertFile) {
            if (-not (Test-Path $CertFile)) { throw "Certificate file not found: $CertFile" }
            $certProps += '-p:AppxPackageSigningEnabled=true'
            $certProps += "-p:PackageCertificateKeyFile=$CertFile"
            if ($CertPassword) { $certProps += "-p:PackageCertificatePassword=$CertPassword" }
        } else {
            $cert = Get-CodeSigningCert -Thumbprint $CertThumbprint
            $certProps += '-p:AppxPackageSigningEnabled=true'
            $certProps += "-p:PackageCertificateThumbprint=$($cert.Thumbprint)"
        }
        $certProps += '-p:GenerateAppxPackageOnBuild=true'
    }

    foreach ($a in $archList) {
        $platform = if ($a -eq 'arm64') { 'ARM64' } else { 'x64' }
        $exe = if ($BrokerExe -and $archList.Count -eq 1) { $BrokerExe } else { $brokerByArch[$a] }
        $dotnetArgs = @(
            'build', $AppProject,
            '-c', $Configuration,
            "-p:Platform=$platform",
            "-p:WSecretBrokerExe=$exe"
        ) + $certProps
        Invoke-Checked -FilePath 'dotnet' -Arguments $dotnetArgs -Label "app ($platform, $Configuration)"
    }
}

# --- Summary ------------------------------------------------------------------

Write-Host ''
Write-Host 'Build complete (build evidence only; no tests or runtime checks were run):' -ForegroundColor Green
foreach ($a in $archList) {
    Write-Host ("  broker[{0}]: {1}" -f $a, $brokerByArch[$a])
}
if ($Package) {
    Write-Host "  MSIX output: $(Join-Path $RepoRoot 'src\WSecret\AppPackages') (git-ignored)"
}
