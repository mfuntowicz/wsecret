#Requires -Version 5.1
<#
.SYNOPSIS
  Run the wsecret/Quick Access test suites and fill a test-evidence file.

.DESCRIPTION
  Runs the Rust workspace tests (including the broker/quick-access acceptance tests when
  present) and any managed test projects, records the exact environment, and writes a
  filled copy of fixtures/quick-access/test-evidence.template.md into evidence\
  (git-ignored). Rows are never marked passed without a real run: the scenario tables in
  the template stay UNEXECUTED until adjudicated against the recorded logs.

.EXAMPLE
  .\scripts\test.ps1
.EXAMPLE
  .\scripts\test.ps1 -SkipManaged -OutDir evidence
#>
[CmdletBinding()]
param(
    [ValidateSet('all', 'workspace', 'app')]
    [string]$Suite = 'all',

    [string]$OutDir = 'evidence',

    [switch]$SkipManaged,
    [switch]$SkipRust
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$Template = Join-Path $RepoRoot 'fixtures\quick-access\test-evidence.template.md'
if (-not (Test-Path $Template)) { throw "Template not found: $Template" }

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
$outAbs = Join-Path $RepoRoot $OutDir
New-Item -ItemType Directory -Force -Path $outAbs | Out-Null
$evidencePath = Join-Path $outAbs "quick-access-test-$stamp.md"
$logPath = Join-Path $outAbs "quick-access-test-$stamp.log"

function Invoke-Capture {
    param([string]$FilePath, [string[]]$Arguments, [string]$Label)
    Add-Content -Path $logPath -Value "=== $Label ===`n>> $FilePath $($Arguments -join ' ')"
    Write-Host ">> $Label" -ForegroundColor Cyan
    $output = & $FilePath @Arguments 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
    Add-Content -Path $logPath -Value ($output -join "`n")
    Add-Content -Path $logPath -Value "=== exit code: $code ===`n"
    return [pscustomobject]@{ Label = $Label; ExitCode = $code; Output = ($output -join "`n") }
}

function Get-Field {
    param([string]$Text)
    if ($null -eq $Text -or $Text -eq '') { return 'UNAVAILABLE' }
    return $Text.Trim()
}

# --- Environment --------------------------------------------------------------

$os = Get-CimInstance -ClassName Win32_OperatingSystem
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
$cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
$gitRev = 'UNAVAILABLE'
try { $gitRev = (git -C $RepoRoot rev-parse HEAD).Trim() } catch { }
$dotnetV = 'UNAVAILABLE'
try { Push-Location $RepoRoot; $dotnetV = (dotnet --version).Trim() } catch { } finally { Pop-Location }
$rustV = 'UNAVAILABLE'
try { $rustV = (rustc --version).Trim() } catch { }
$cargoV = 'UNAVAILABLE'
try { $cargoV = (cargo --version).Trim() } catch { }

$envRows = @{
    'Date \(UTC\)'                        = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    'Machine \(model/CPU/RAM\)'           = "$(Get-Field $cs.Model) / $(Get-Field $cpu.Name) / $([math]::Round($cs.TotalPhysicalMemory / 1GiB, 1)) GiB"
    'OS edition/build'                    = "$($os.Caption) build $($os.BuildNumber)"
    'Architecture \(x64/ARM64 native\?\)' = "$env:PROCESSOR_ARCHITECTURE (native execution of this host only)"
    '\.NET SDK / Rust / MSVC versions'    = "dotnet $dotnetV / $rustV / $cargoV"
    'Build configuration & git revision'  = "Debug+Release test run; git $gitRev"
    'Store fixture \(manifest id / sha256\)' = "see run logs; synthetic stores per fixtures/quick-access/manifest.json"
}

# --- Runs ---------------------------------------------------------------------

$runs = @()
$failed = $false

if ($Suite -in @('all', 'workspace') -and -not $SkipRust) {
    $runs += Invoke-Capture -FilePath 'cargo' `
        -Arguments @('test', '--workspace', '--locked', '--', '--test-threads=1') `
        -Label 'cargo test --workspace --locked'
    if ($runs[-1].ExitCode -ne 0) { $failed = $true }
}

if ($Suite -in @('all', 'app') -and -not $SkipManaged) {
    $testProjects = @(Get-ChildItem -Path (Join-Path $RepoRoot 'src') -Recurse -Filter '*Tests*.csproj' -ErrorAction SilentlyContinue)
    if ($testProjects.Count -eq 0) {
        $runs += [pscustomobject]@{
            Label    = 'dotnet test (managed)'
            ExitCode = $null
            Output   = 'UNEXECUTED - no managed test project (*Tests*.csproj) found under src\'
        }
    } else {
        foreach ($p in $testProjects) {
            $runs += Invoke-Capture -FilePath 'dotnet' -Arguments @('test', $p.FullName, '-c', 'Debug') -Label "dotnet test $($p.Name)"
            if ($runs[-1].ExitCode -ne 0) { $failed = $true }
        }
    }
}

# --- Fill the evidence file ---------------------------------------------------

$summary = New-Object System.Collections.Generic.List[string]
$summary.Add('## Automated runs (filled by scripts/test.ps1)')
$summary.Add('')
$summary.Add('| Command | Exit code | Result summary | Log |')
$summary.Add('|---|---|---|---|')
foreach ($r in $runs) {
    $codes = [regex]::Matches($r.Output, 'test result: (ok|FAILED)\.\s+(\d+) passed;\s+(\d+) failed') |
        ForEach-Object { $_.Groups[2].Value + ' passed, ' + $_.Groups[3].Value + ' failed' }
    $resultText = if ($codes.Count -gt 0) { ($codes -join '; ') } elseif ($r.ExitCode -eq $null) { $r.Output } else { "exit $($r.ExitCode) - see log" }
    $summary.Add("| $($r.Label) | $(if ($null -eq $r.ExitCode) { 'UNEXECUTED' } else { $r.ExitCode }) | $resultText | $(Split-Path -Leaf $logPath) |")
}

$text = Get-Content $Template -Raw
foreach ($k in $envRows.Keys) {
    $value = $envRows[$k]
    $text = [regex]::Replace($text, "(?m)^(\| $k \| )UNEXECUTED( \|)$", { param($m) $m.Groups[1].Value + $value + $m.Groups[2].Value })
}
# Replace the "Automated runs" placeholder section with the real one.
$summaryBlock = ($summary -join "`n") + "`n`n"
$text = [regex]::Replace($text, '(?s)## Automated runs \(filled by scripts/test\.ps1\).*?(?=## Notes)', { param($m) $summaryBlock })

Set-Content -Path $evidencePath -Value $text -Encoding UTF8

Write-Host ''
Write-Host "Evidence file: $evidencePath" -ForegroundColor Green
Write-Host "Full log:      $logPath"
Write-Host 'Scenario tables remain UNEXECUTED until adjudicated against these logs.'
if ($failed) {
    Write-Host 'One or more executed runs FAILED - see the log.' -ForegroundColor Red
    exit 1
}
exit 0
