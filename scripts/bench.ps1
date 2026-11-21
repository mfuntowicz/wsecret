#Requires -Version 5.1
<#
.SYNOPSIS
  Measure Quick Access performance against the preregistered budgets.

.DESCRIPTION
  Builds the packaged Release configuration, materializes the synthetic corpus store
  (fixtures/quick-access/manifest.json "perf_corpus"), runs each measurement harness
  listed in fixtures/quick-access/bench-budgets.json, computes p50/p95/p99/min/max from
  the harness samples, and fills a copy of fixtures/quick-access/bench-evidence.template.md
  into evidence\ (git-ignored).

  A measurement whose harness is absent (null) or fails is recorded UNEXECUTED. This
  script never estimates a value it did not measure.

  Harness contract: `command` is a string with {STORE}, {SAMPLES}, {OUT} placeholders;
  it prints one latency sample in milliseconds (invariant-culture decimal) per stdout
  line. Packaged Release, AC power, no debugger.

.EXAMPLE
  .\scripts\bench.ps1 -Samples 100
.EXAMPLE
  .\scripts\bench.ps1 -Arch x64 -StorePath .\target\qa\perf-store.secret -SkipBuild
#>
[CmdletBinding()]
param(
    [ValidateSet('x64', 'arm64')]
    [string]$Arch = 'x64',

    [ValidateRange(1, 100000)]
    [int]$Samples = 100,

    # Use an existing corpus store instead of generating one.
    [string]$StorePath = '',

    [switch]$SkipBuild,
    [string]$OutDir = 'evidence'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$BudgetsPath = Join-Path $RepoRoot 'fixtures\quick-access\bench-budgets.json'
$Template = Join-Path $RepoRoot 'fixtures\quick-access\bench-evidence.template.md'
if (-not (Test-Path $BudgetsPath)) { throw "Budgets not found: $BudgetsPath" }
if (-not (Test-Path $Template)) { throw "Template not found: $Template" }

$budgets = Get-Content $BudgetsPath -Raw | ConvertFrom-Json
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
$outAbs = Join-Path $RepoRoot $OutDir
New-Item -ItemType Directory -Force -Path $outAbs | Out-Null
$evidencePath = Join-Path $outAbs "quick-access-bench-$stamp.md"
$logPath = Join-Path $outAbs "quick-access-bench-$stamp.log"

function Invoke-Harness {
    param([string]$CommandTemplate, [string]$Store, [int]$N, [string]$OutFile)
    $cmd = $CommandTemplate.Replace('{STORE}', $Store).Replace('{SAMPLES}', "$N").Replace('{OUT}', $OutFile)
    Add-Content -Path $logPath -Value "=== harness ===`n$cmd"
    $output = Invoke-Expression $cmd 2>&1 | ForEach-Object { "$_" }
    Add-Content -Path $logPath -Value ($output -join "`n")
    $samples = New-Object System.Collections.Generic.List[double]
    foreach ($line in $output) {
        $t = $line.Trim()
        if ($t -match '^[0-9]+(\.[0-9]+)?$') {
            $samples.Add([double]::Parse($t, [Globalization.CultureInfo]::InvariantCulture))
        }
    }
    return $samples
}

function Get-Percentile {
    param([double[]]$Sorted, [double]$P)
    if ($Sorted.Count -eq 0) { return $null }
    $idx = [math]::Ceiling($P / 100.0 * $Sorted.Count) - 1
    if ($idx -lt 0) { $idx = 0 }
    if ($idx -ge $Sorted.Count) { $idx = $Sorted.Count - 1 }
    return $Sorted[$idx]
}

# --- Build (packaged Release) -------------------------------------------------

if (-not $SkipBuild) {
    & (Join-Path $PSScriptRoot 'build.ps1') -Arch $Arch -Configuration Release -Package
    if ($LASTEXITCODE -ne 0) { throw 'build.ps1 failed; cannot benchmark' }
}

# --- Corpus store -------------------------------------------------------------

$store = $StorePath
if (-not $store) {
    $corpusHarness = $budgets.corpus.harness
    if ($corpusHarness) {
        $storeOut = Join-Path $outAbs "perf-store-$stamp.secret"
        $null = Invoke-Harness -CommandTemplate $corpusHarness -Store $storeOut -N $Samples -OutFile (Join-Path $outAbs "corpus-$stamp.txt")
        $store = $storeOut
    }
}
if (-not $store -or -not (Test-Path $store)) {
    Write-Warning 'No corpus store available (-StorePath or corpus harness); corpus-dependent rows will be UNEXECUTED.'
    $store = ''
}

# --- Measurements -------------------------------------------------------------

$rows = @{}
$harnessRows = New-Object System.Collections.Generic.List[string]
$harnessRows.Add('| Measurement | Harness command | Stdout parse | Log |')
$harnessRows.Add('|---|---|---|---|')

foreach ($m in $budgets.measurements) {
    $id = $m.id
    if (-not $m.harness) {
        $rows[$id] = @{ Samples = 'UNEXECUTED'; P50 = ''; P95 = ''; P99 = ''; Min = ''; Max = ''; Verdict = 'UNEXECUTED - harness absent' }
        $harnessRows.Add("| $id | (none) | - | - |")
        continue
    }
    if (-not $store -and $id -ne 'idle-steady') {
        $rows[$id] = @{ Samples = 'UNEXECUTED'; P50 = ''; P95 = ''; P99 = ''; Min = ''; Max = ''; Verdict = 'UNEXECUTED - no corpus store' }
        $harnessRows.Add("| $id | (corpus store unavailable) | - | - |")
        continue
    }

    $runOut = Join-Path $outAbs "bench-$id-$stamp.txt"
    $samples = $null
    try {
        $samples = Invoke-Harness -CommandTemplate $m.harness -Store $store -N $Samples -OutFile $runOut
    } catch {
        Write-Warning "harness for $id failed: $_"
    }
    if (-not $samples -or $samples.Count -eq 0) {
        $rows[$id] = @{ Samples = 'UNEXECUTED'; P50 = ''; P95 = ''; P99 = ''; Min = ''; Max = ''; Verdict = 'UNEXECUTED - harness produced no samples' }
        $harnessRows.Add("| $id | $($m.harness) | no samples | $(Split-Path -Leaf $logPath) |")
        continue
    }

    $sorted = @($samples | Sort-Object)
    $p50 = Get-Percentile -Sorted $sorted -P 50
    $p95 = Get-Percentile -Sorted $sorted -P 95
    $p99 = Get-Percentile -Sorted $sorted -P 99
    $p95max = $null
    if ($m.budget -isnot [string]) {
        $bp = $m.budget.PSObject.Properties['p95_ms_max']
        if ($bp) { $p95max = $bp.Value }
    }
    $verdict = 'recorded (no fixed target)'
    if ($null -ne $p95max) {
        $verdict = if ($p95 -le [double]$p95max) { "within budget (p95 <= $p95max ms)" } else { "BUDGET EXCEEDED (p95 > $p95max ms)" }
    }
    $rows[$id] = @{
        Samples = "$($samples.Count)"
        P50 = "$p50"; P95 = "$p95"; P99 = "$p99"
        Min = "$($sorted[0])"; Max = "$($sorted[$sorted.Count - 1])"
        Verdict = $verdict
    }
    $harnessRows.Add("| $id | $($m.harness) | $($samples.Count) samples | $(Split-Path -Leaf $logPath) |")
}

# --- Fill the evidence file ---------------------------------------------------

$os = Get-CimInstance -ClassName Win32_OperatingSystem
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
$cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
$gitRev = 'UNAVAILABLE'
try { $gitRev = (git -C $RepoRoot rev-parse HEAD).Trim() } catch { }

# Literal row-name -> value substitutions (matched by prefix, no regex).
$envRows = [ordered]@{
    'Date (UTC)'                          = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    'Reference machine (model)'           = "$(if ($cs.Model) { $cs.Model.Trim() } else { 'UNAVAILABLE' })"
    'CPU / RAM'                           = "$(if ($cpu.Name) { $cpu.Name.Trim() } else { 'UNAVAILABLE' }) / $([math]::Round($cs.TotalPhysicalMemory / 1GiB, 1)) GiB"
    'OS edition/build'                    = "$($os.Caption) build $($os.BuildNumber)"
    'Architecture (x64/ARM64 — native execution?)' = "$env:PROCESSOR_ARCHITECTURE (state explicitly whether native)"
    'Build configuration & git revision'  = "Release packaged; git $gitRev"
    'Store corpus (manifest recipe / record count / sha256)' = $(if ($store) { "$store (see log for recipe)" } else { 'UNAVAILABLE' })
}

$outLines = New-Object System.Collections.Generic.List[string]
$skipProvenanceRows = $false
foreach ($line in (Get-Content $Template)) {
    if ($skipProvenanceRows) {
        if ($line -eq '' -or $line.StartsWith('## ')) { $skipProvenanceRows = $false }
        else { continue }
    }
    $done = $false

    foreach ($name in $envRows.Keys) {
        if ($line.StartsWith("| $name | UNEXECUTED |")) {
            $outLines.Add("| $name | $($envRows[$name]) |")
            $done = $true
            break
        }
    }
    if (-not $done) {
        foreach ($id in $rows.Keys) {
            if ($line.StartsWith("| $id |")) {
                $r = $rows[$id]
                $outLines.Add("| $id | (see harness provenance) | $($r.Samples) | $($r.P50) | $($r.P95) | $($r.P99) | $($r.Min) | $($r.Max) | (see budgets) | $($r.Verdict) |")
                $done = $true
                break
            }
        }
    }
    if (-not $done) {
        if ($line.StartsWith('| Measurement | Harness command |')) {
            foreach ($h in $harnessRows) { $outLines.Add($h) }
            $skipProvenanceRows = $true
        } else {
            $outLines.Add($line)
        }
    }
}
$text = $outLines -join "`n"

Set-Content -Path $evidencePath -Value $text -Encoding UTF8

Write-Host ''
Write-Host "Bench evidence: $evidencePath" -ForegroundColor Green
Write-Host "Full log:       $logPath"
foreach ($id in $rows.Keys) {
    Write-Host ("  {0}: {1}" -f $id, $rows[$id].Verdict)
}
