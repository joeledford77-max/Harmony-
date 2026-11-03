# setup_windows.ps1 - make this Windows PC a Harmony mesh node. Safe to run again.
#
#   powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1
#
# Expects next to it (win_node.sh stages them on the laptop; one scp line copies them here):
# rust_p2p_node.exe (cross-compiled on the laptop), node.ps1, node.cmd, harmony.env and one
# llama-3.2-*-instruct.gguf model. It then:
#   1. checks those files                  2. reports this PC: CPU, RAM, temperature sensor
#   3. downloads llama.cpp's Windows CPU build from GitHub into .\llama (no installer, no admin)
#   4. writes harmony.env, and adds one firewall rule (asks for admin): inbound TCP 3005-3015,
#      only to rust_p2p_node.exe, only from this local network
#   5. starts the node in the background (node.cmd) and shows its status
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$Dir = $PSScriptRoot
Set-Location -Path $Dir
$RuleName = 'Harmony mesh node'

function Step([string]$m) { Write-Host ''; Write-Host "== $m ==" -ForegroundColor Cyan }
function Ok([string]$m) { Write-Host 'OK   ' -ForegroundColor Green -NoNewline; Write-Host $m }
function Warn([string]$m) { Write-Host 'WARN ' -ForegroundColor Yellow -NoNewline; Write-Host $m }
function Halt([string]$m) { Write-Host 'STOP ' -ForegroundColor Red -NoNewline; Write-Host $m; exit 1 }

# ------------------------------------------------------------------ 1. files
Step '1/5 files'
foreach ($f in @('rust_p2p_node.exe', 'node.ps1', 'node.cmd', 'harmony.env')) {
    if (-not (Test-Path (Join-Path $Dir $f))) { Halt "$f is missing in $Dir (run the scp line again)" }
}
$model = Get-ChildItem -Path $Dir -Filter 'llama-3.2-*.gguf' | Sort-Object Length | Select-Object -Last 1
if (-not $model) { Halt "no llama-3.2 model (.gguf) in $Dir (run the scp line again)" }
$exeSize = (Get-Item (Join-Path $Dir 'rust_p2p_node.exe')).Length
Ok ("rust_p2p_node.exe ({0:N1} MB), model {1} ({2:N2} GB)" -f ($exeSize / 1MB), $model.Name, ($model.Length / 1GB))

# ------------------------------------------------------------------ 2. this PC
Step '2/5 this PC'
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
$ramGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
$cpu = (Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1).Name.Trim()
Ok "$cpu, $ramGB GB RAM, $([Environment]::OSVersion.VersionString)"
$tier = if ($model.Name -match '3b') { 'standard' } else { 'light' }
if ($tier -eq 'standard' -and $ramGB -lt 7.5) {
    Warn "the 3B model wants about 3 GB free; with $ramGB GB RAM the 1B model is safer (on the phone: bash win_node.sh, without NOTEBOOK_TIER)"
}
$k = (Get-CimInstance -ClassName Win32_PerfFormattedData_Counters_ThermalZoneInformation -ErrorAction SilentlyContinue |
    Measure-Object -Property Temperature -Maximum -ErrorAction SilentlyContinue).Maximum
if ($k -gt 0) { Ok ("temperature sensor: the thermal zones report {0:N1} C" -f ($k - 273.15)) }
else { Warn 'no thermal zone reports a temperature on this PC: the node will report a safe-but-unknown 40 C' }

# ------------------------------------------------------------------ 3. llama.cpp
Step '3/5 llama.cpp (Windows CPU build)'
$llamaDir = Join-Path $Dir 'llama'
function Find-Llama {
    if (-not (Test-Path $llamaDir)) { return $null }
    $c = Get-ChildItem -Path $llamaDir -Recurse -Filter 'llama-completion.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $c) { $c = Get-ChildItem -Path $llamaDir -Recurse -Filter 'llama-cli.exe' -ErrorAction SilentlyContinue | Select-Object -First 1 }
    return $c
}
$bin = Find-Llama
if ($bin) {
    Ok "already here: $($bin.FullName)"
} else {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try {
        $rels = Invoke-RestMethod -Uri 'https://api.github.com/repos/ggml-org/llama.cpp/releases?per_page=20' -Headers @{ 'User-Agent' = 'harmony-setup' }
    } catch { Halt "cannot reach GitHub for llama.cpp: $($_.Exception.Message)" }
    $asset = $rels | ForEach-Object { $_.assets } | Where-Object { $_.name -match '^llama-b\d+-bin-win-cpu-x64\.zip$' } | Select-Object -First 1
    if (-not $asset) { Halt 'no llama-b*-bin-win-cpu-x64.zip in the recent llama.cpp releases' }
    $zip = Join-Path $Dir $asset.name
    Write-Host ("     downloading {0} ({1:N0} MB)..." -f $asset.name, ($asset.size / 1MB))
    try { Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip -UseBasicParsing }
    catch { Halt "download failed: $($_.Exception.Message)" }
    Expand-Archive -Path $zip -DestinationPath $llamaDir -Force
    Remove-Item -Force -Path $zip
    $bin = Find-Llama
    if (-not $bin) { Halt "the zip has no llama-completion.exe or llama-cli.exe ($llamaDir)" }
    Ok "$($asset.name) -> $($bin.FullName)"
}

# Does it start? Exit code 0xC0000135 (-1073741515) means a DLL is missing: the Visual C++ runtime.
function Test-Llama {
    $out = Join-Path $Dir 'llama_version.txt'
    $err = Join-Path $Dir 'llama_version.err'
    $p = Start-Process -FilePath $bin.FullName -ArgumentList '--version' -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $out -RedirectStandardError $err
    return $p.ExitCode
}
$code = Test-Llama
if ($code -eq -1073741515) {
    Warn 'llama.cpp needs the Microsoft Visual C++ runtime; installing it with winget (approve the prompt)...'
    winget install --id Microsoft.VCRedist.2015+.x64 -e --accept-source-agreements --accept-package-agreements
    $code = Test-Llama
}
$ver = (Get-Content -Path (Join-Path $Dir 'llama_version.err') -ErrorAction SilentlyContinue | Select-String -Pattern 'version' | Select-Object -First 1)
if ($code -eq 0) { Ok "llama.cpp runs: $(if ($ver) { $ver.Line.Trim() } else { $bin.Name })" }
else { Warn "llama.cpp --version exited $code; jobs and advisories on this PC may fail (see $Dir\llama_version.err)" }

# ------------------------------------------------------------------ 4. settings + firewall
Step '4/5 settings and firewall'
$envFile = Join-Path $Dir 'harmony.env'
$keep = @(Get-Content -Path $envFile | Where-Object { $_ -notmatch '^HARMONY_(LLAMA_BIN|MODEL_TIER|MODEL_PATH)=' })
$lines = $keep + @("HARMONY_LLAMA_BIN=$($bin.FullName)", "HARMONY_MODEL_TIER=$tier", "HARMONY_MODEL_PATH=$($model.FullName)")
Set-Content -Path $envFile -Value $lines -Encoding ASCII
$names = ($lines | Where-Object { $_ -match '^HARMONY_' } | ForEach-Object { ($_ -split '=')[0] }) -join ' '
Ok "harmony.env: $names"
foreach ($l in $lines) { if ($l -match '^HARMONY_(PEERS|LABEL)=') { Write-Host "     $l" } }

$exe = Join-Path $Dir 'rust_p2p_node.exe'
$rule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
$ruleApp = if ($rule) { ($rule | Get-NetFirewallApplicationFilter).Program } else { $null }
if ($rule -and $ruleApp -eq $exe) {
    Ok 'firewall rule already in place'
} else {
    $fw = "Remove-NetFirewallRule -DisplayName '$RuleName' -ErrorAction SilentlyContinue; " +
          "New-NetFirewallRule -DisplayName '$RuleName' -Direction Inbound -Action Allow -Program '$exe' " +
          "-Protocol TCP -LocalPort 3005-3015 -RemoteAddress LocalSubnet -Profile Any | Out-Null"
    Write-Host '     adding the firewall rule: approve the administrator prompt...'
    try {
        Start-Process -FilePath 'powershell' -Verb RunAs -Wait -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $fw)
    } catch { Warn "not added ($($_.Exception.Message))" }
    if (Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue) {
        Ok 'firewall: inbound TCP 3005-3015 allowed for rust_p2p_node.exe, from this local network only'
    } else {
        Warn 'no firewall rule: this PC can reach the others, but they cannot reach it (offloaded jobs fail). Run setup again and approve the prompt.'
    }
}

# ------------------------------------------------------------------ 5. start
Step '5/5 start the node'
& (Join-Path $Dir 'node.ps1') restart
Write-Host ''
Write-Host 'This PC is now a mesh node. In this folder:'
Write-Host '  .\node.cmd status | stop | start | restart | log'
Write-Host 'On the phone: bash ~/node.sh status  (should show 2 peers), dashboard http://127.0.0.1:3005/ui'
Write-Host 'Keep this PC plugged in and awake: a sleeping PC drops out of the mesh until it wakes.'
