# Building, packaging, and running WSecret Quick Access

Reproducible commands for the packaged WinUI 3 app (`WSecret.exe`) and its Rust broker
(`wsecret-broker.exe`) on **x64** and **ARM64**. All commands run from the repository
root on Windows 11. Feature contract: [quick-access.md](quick-access.md); security:
[threat-model.md](threat-model.md).

**Evidence status:** x64 and ARM64 Release builds and development-signed MSIX packages
have been produced and signature-verified. The x64 package is installed and passed
packaged passphrase unlock and explicit Lock. Native tests/UI acceptance, Hello PRF
enrollment/unlock/recovery, and performance samples are recorded in
`../evidence/quick-access-20261120.md`. ARM64 remains cross-build evidence only.

## 1. Pinned toolchain

| Tool | Pin | Source of truth |
|---|---|---|
| .NET SDK | **11.0.100** | `global.json` |
| Rust | **1.100.0** | `rust-toolchain.toml` |
| Windows App SDK (NuGet) | **2.7.0** | `src/WSecret/WSecret.csproj` |
| TFM / min OS | `net11.0-windows10.0.26100.0` / Windows 11 build **26100** | `WSecret.csproj`, `Package.appxmanifest` |
| MSVC + Windows SDK | MSVC v143+ with a Windows SDK ≥ 10.0.26100.0 | build host |
| NuGet feed | nuget.org only (package source mapping) | `NuGet.config` |

Additional restore-time packages (from NuGet, no workload installs required): Windows App
SDK 2.7.0 (self-contained runtime), and the single-project MSIX packaging targets —
either the Visual Studio single-project MSIX tooling or
`Microsoft.Windows.SDK.BuildTools` (for `makeappx`/`makepri`/`signtool`). Cargo
dependencies are pinned by the committed `Cargo.lock` (`--locked` everywhere).

Check the pins before building:

```powershell
dotnet --version      # must print 11.0.100
rustc --version       # must print 1.100.0
```

## 2. Layout

| Path | Contents |
|---|---|
| `crates/libhydrogen-sys/`, `crates/wsecret-core/`, `crates/wsecret-cli/` | existing library and CLI (unchanged by Quick Access) |
| `crates/wsecret-broker/` | Rust broker binary `wsecret-broker.exe` |
| `src/WSecret/WSecret.csproj` | WinUI 3 app (`WSecret`), single-project MSIX |
| `src/WSecret/Package.appxmanifest` | package identity `com.wsecret.QuickAccess` / `CN=WSecret` |
| `WSecret.sln`, `global.json`, `Directory.Build.props`, `NuGet.config` | solution and pin files |
| `scripts/` | `build.ps1`, `test.ps1`, `bench.ps1` |
| `fixtures/quick-access/` | fixture recipes, budgets, evidence templates |

## 3. Build

Regenerate the MSIX tiles, window icon, and multi-resolution executable/tray icon from
`src/WSecret/Assets/WSecret.png` when the source logo changes:

```powershell
.\scripts\generate-icons.ps1
```

The driver script builds the broker for the requested architecture, then the app:

```powershell
# x64 (default): broker + app, Debug or Release
.\scripts\build.ps1 -Arch x64 -Configuration Release

# ARM64 broker + ARM64 app
.\scripts\build.ps1 -Arch arm64 -Configuration Release

# both architectures
.\scripts\build.ps1 -Arch both -Configuration Release
```

Equivalent manual commands (what the script runs):

```powershell
# Broker — x64
cargo build -p wsecret-broker --release --locked --target x86_64-pc-windows-msvc
#   -> target\x86_64-pc-windows-msvc\release\wsecret-broker.exe

# Broker — ARM64 (cross-compile; runtime unverified without ARM64 hardware)
cargo build -p wsecret-broker --release --locked --target aarch64-pc-windows-msvc
#   -> target\aarch64-pc-windows-msvc\release\wsecret-broker.exe

# App — x64 (the broker exe is copied into the package as wsecret-broker.exe)
dotnet build src\WSecret\WSecret.csproj -c Release -p:Platform=x64 `
  -p:WSecretBrokerExe=$PWD\target\x86_64-pc-windows-msvc\release\wsecret-broker.exe

# App — ARM64
dotnet build src\WSecret\WSecret.csproj -c Release -p:Platform=ARM64 `
  -p:WSecretBrokerExe=$PWD\target\aarch64-pc-windows-msvc\release\wsecret-broker.exe
```

The app fails visibly if `wsecret-broker.exe` is missing from the package; there is no
fallback path.

## 4. Package (MSIX) and signing

Packaged MSIX is the only supported delivery; there is no unpackaged mode. The Publisher
is fixed at `CN=WSecret`, so **any** signing certificate must have exactly that subject.

```powershell
# Build + sign the MSIX in one step (auto-provisions a dev cert if needed)
.\scripts\build.ps1 -Arch x64 -Configuration Release -Package

# Bring your own signing identity
.\scripts\build.ps1 -Arch x64 -Configuration Release -Package -CertThumbprint <thumb>
.\scripts\build.ps1 -Arch x64 -Configuration Release -Package -CertFile .\cert.pfx -CertPassword <pw>
```

What the script does for `-Package`:

1. Finds or creates a code-signing certificate with subject `CN=WSecret` in
   `CurrentUser\My` (self-signed for local development; the public part is exported to
   `dist\wsecret-dev.cer`, which is git-ignored).
2. Runs the packaging build with signing driven by MSBuild properties:
   `dotnet build … -p:GenerateAppxPackageOnBuild=true -p:AppxPackageSigningEnabled=true
   -p:PackageCertificateThumbprint=<thumb>` (or `-p:PackageCertificateKeyFile=…`
   `-p:PackageCertificatePassword=…`).
3. Leaves the signed package under `src\WSecret\AppPackages\` (git-ignored).

Signing keys never enter source control: `*.pfx`, `*.p12`, and `dist/` are ignored. CI
should supply a real `CN=WSecret` certificate from its secret store.

Verified packaging commands used for the current artifacts (development-only PFX in
`%TEMP%`, never committed):

```powershell
winapp pack src/WSecret/WSecret.csproj -c Release --arch x64 `
  -p "WSecretBrokerExe=$PWD/target/x86_64-pc-windows-msvc/release/wsecret-broker.exe" `
  --cert "$env:TEMP/wsecret-devcert.pfx" --cert-password wsecret-development-only `
  --output artifacts/WSecret-x64.msix
winapp pack src/WSecret/WSecret.csproj -c Release --arch arm64 `
  --cert "$env:TEMP/wsecret-devcert.pfx" --cert-password wsecret-development-only `
  --output artifacts/WSecret-arm64.msix `
  -p "WSecretBrokerExe=$PWD/target/aarch64-pc-windows-msvc/release/wsecret-broker.exe"
```

The development-signed **0.2.1.1** packages pass `signtool verify /pa`. The installed x64
package (`com.wsecret.QuickAccess_j9amz7x94kate`) passed the search-palette scenarios in
[the release evidence](../evidence/quick-access-20261120.md#logo-and-copy-stability-release-0211).
ARM64 was cross-built and signature-checked, not executed.

## 5. Install and run

```powershell
# Trust the self-signed dev certificate first (local development only)
Import-Certificate -FilePath .\dist\wsecret-dev.cer -CertStoreLocation Cert:\CurrentUser\Root

# Install the package for the current user
Add-AppxPackage -Path .\artifacts\WSecret-x64.msix

# Launch (AUMID: <PackageFamilyName>!WSecret)
explorer.exe shell:AppsFolder\com.wsecret.QuickAccess_<hash>!WSecret
```

The exact package folder/file name depends on the MSBuild packaging output; use the
`.msix` produced under `src\WSecret\AppPackages\`. The app registers the global hotkey
(default `Ctrl+Alt+W`) and the tray icon on first launch; launch-at-sign-in is the
packaged startup task `WSecretStartup`. Uninstall with
`Get-AppxPackage com.wsecret.QuickAccess | Remove-AppxPackage`.

## 6. Test and benchmark

```powershell
# Workspace tests + quick-access acceptance rows; fills a test evidence file
.\scripts\test.ps1

# Performance measurements against fixtures/quick-access/bench-budgets.json
.\scripts\bench.ps1 -Samples 100
```

Both scripts record the exact environment (OS build, architecture, tool versions, git
revision) and write filled copies of the templates in `fixtures\quick-access\` into the
git-ignored `evidence\` directory. Rows that could not run are recorded **UNEXECUTED**;
the scripts never mark a row passed without a real run.

## 7. Architecture matrix

| Target | Broker command | App platform | Status |
|---|---|---|---|
| Windows 11 x64 | `--target x86_64-pc-windows-msvc` | `-p:Platform=x64` | installed; packaged passphrase unlock and explicit Lock executed |
| Windows 11 ARM64 | `--target aarch64-pc-windows-msvc` | `-p:Platform=ARM64` | cross-build only until run on ARM64 hardware |

Required future evidence: separate **native** runs on x64 and ARM64 hosts (build, install,
unlock, copy, write, lock). A successful ARM64 cross-compile on an x64 host is never
reported as ARM64 runtime proof.
