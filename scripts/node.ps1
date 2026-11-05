# node.ps1 - start, stop, restart and check this Windows PC's rust_p2p_node, gracefully.
# Run it through node.cmd (no PowerShell policy change needed), from the harmony folder:
#
#   .\node.cmd start     start it hidden in the background; refuses if one is already running;
#                        waits until it says ready
#   .\node.cmd stop      graceful: the node refuses new jobs, says goodbye to its peers (they drop
#                        it at once), finishes in-flight work, exits. Forced only if it is still
#                        running after 30 s.
#   .\node.cmd restart   stop + start
#   .\node.cmd status    which build answers, its pid, state, temperature, peers, AI placement
#   .\node.cmd log       follow the node's log (Ctrl+C to stop following)
#
#   .\node.cmd autosync user@laptop   one time: keep this PC on the mesh's build by itself. Makes
#                        an ssh key for the laptop, which takes it locked to its sync gate (asks
#                        the laptop's password once), installs the build mesh_upgrade.sh left on
#                        the laptop, and starts a hidden watcher, now and at every logon, that
#                        checks the laptop every 15 s, installs each new build and tells the
#                        laptop how each sync went, so mesh_upgrade.sh sees all three devices on
#                        the same build, or why not. A build goes in only if the phone signed it
#                        (checked by the node already here) and it was not signed before the
#                        installed one; if the new node does not start, the previous one is put
#                        back. The watcher also restarts the node if it stops, unless you stopped
#                        it. Run autosync again to restart the watcher: a running watcher keeps the
#                        node.ps1 it started with, and its syncs say so when a newer one is here.
#   .\node.cmd sync      check the laptop for a new build once, now (also retries a build the
#                        watcher stopped retrying)
#
#   $env:HARMONY_MOCK_TEMP = 80; .\node.cmd restart    demo: report 80 C until the next restart
#
# Settings live next to this script in harmony.env as HARMONY_* lines (win_node.sh and
# setup_windows.ps1 write it; each build's mesh.env updates the trust list and the advisor), plus
# SYNC_FROM (autosync), UPDATE_SIGNER (whose signature a build needs: pinned from the first signed
# build), UPDATE_ISSUED (when the installed build was signed) and SYNC_KEY_LOCKED. The node keeps
# its identity in %USERPROFILE%\.harmony.
param([string]$Command = 'status', [string]$Arg = '')

$Dir = $PSScriptRoot
$Exe = Join-Path $Dir 'rust_p2p_node.exe'
$Log = Join-Path $Dir 'p2p.log'
$ErrLog = Join-Path $Dir 'p2p.err.log'
$EnvFile = Join-Path $Dir 'harmony.env'
$StopWait = 30
$StartWait = 45
$StopFlag = Join-Path $Dir 'stopped.flag'      # stopped on purpose: the watcher leaves it stopped
$BuildFile = Join-Path $Dir 'BUILD'            # the build the last sync installed
$SyncLog = Join-Path $Dir 'sync.log'
$SyncStatus = Join-Path $Dir 'sync.status'     # the last sync's one-line result, for the watcher
$MeshEnv = Join-Path $Dir 'mesh.env'           # mesh settings from the installed build (signed with it)
$SyncKey = Join-Path $env:USERPROFILE '.ssh\harmony_sync'
$TaskName = 'Harmony node'
$PsExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$SkipFile = Join-Path $Dir 'sync.skip'         # a staged build that failed here: not fetched again every round
$ReportFile = Join-Path $Dir 'sync.reported'   # what the laptop was last told about the syncs here, and when
$WatchPid = Join-Path $Dir 'watch.pid'         # the running watcher, written once it holds its lock
$WatchEvery = 15                               # seconds between the watcher's checks
$WatchRev = '2'                                # the watcher's loop; a sync started by an older one says so

function Ok([string]$m) { Write-Host 'OK   ' -ForegroundColor Green -NoNewline; Write-Host $m }
function Warn([string]$m) { Write-Host 'WARN ' -ForegroundColor Yellow -NoNewline; Write-Host $m }
function Bad([string]$m) { Write-Host 'FAIL ' -ForegroundColor Red -NoNewline; Write-Host $m }
function Note([string]$m) { Write-Host "     $m" }
function Remove-Ansi([string]$s) { return ($s -replace "$([char]27)\[[0-9;]*m", '') }

function Get-NodeProcs { return @(Get-Process -Name 'rust_p2p_node' -ErrorAction SilentlyContinue) }

# The port the node announced in its log (it moves off 3005 when something else holds it).
function Get-LogPort {
    if (-not (Test-Path $Log)) { return $null }
    $hit = Get-Content -Path $Log -Encoding UTF8 -ErrorAction SilentlyContinue |
        Select-String -Pattern 'mesh API on http://\S+:(\d+)' | Select-Object -Last 1
    if ($hit) { return [int]$hit.Matches[0].Groups[1].Value }
    return $null
}

function Get-Health([int]$Port) {
    try { return Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -TimeoutSec 3 } catch { return $null }
}

function Show-LogLines([string]$Pattern) {
    foreach ($f in @($Log, $ErrLog)) {
        if (Test-Path $f) {
            Get-Content -Path $f -Encoding UTF8 -ErrorAction SilentlyContinue |
                Select-String -Pattern $Pattern | Select-Object -Last 3 |
                ForEach-Object { Note (Remove-Ansi $_.Line) }
        }
    }
}

function Import-NodeEnv {
    if (-not (Test-Path $EnvFile)) { Warn "no $EnvFile; starting with defaults"; return }
    foreach ($line in Get-Content -Path $EnvFile) {
        if ($line -match '^\s*(HARMONY_[A-Z_]+)=(.*)$') {
            [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2].Trim(), 'Process')
        }
    }
}

function Show-Status {
    $p = Get-NodeProcs
    if ($p.Count -eq 0) { Bad 'not running   (start: .\node.cmd start)'; return $false }
    $port = Get-LogPort
    if (-not $port) { $port = 3005 }
    $h = Get-Health $port
    if (-not $h) { Bad "pid $($p[0].Id) is running but nothing answers on :$port"; return $false }
    $node = [string]$h.node
    if ($node.Length -gt 12) { $node = $node.Substring(0, 12) }
    $build = if ($h.build) { $h.build } else { 'pre-v10 build' }
    $state = if ($h.state) { $h.state } else { 'ready' }
    Ok ("pid {0} - {1} - {2} - :{3} - {4} {5}" -f $p[0].Id, $build, $state, $port, $h.label, $node)
    if ($h.pid -and [int]$h.pid -ne $p[0].Id) { Warn "the node answering on :$port is pid $($h.pid), not $($p[0].Id)" }
    Note ("temperature {0:N1} C / limit {1} - model {2} - {3} peer(s)" -f [double]$h.thermal_c, $h.max_temp, $h.tier, $h.peers)
    if ($env:HARMONY_MOCK_TEMP) { Note "(MOCK: HARMONY_MOCK_TEMP=$($env:HARMONY_MOCK_TEMP) in this window)" }
    if ($h.placement) {
        $veto = if ($h.placement.veto_now) { " - vetoed: $($h.placement.veto_now)" } else { '' }
        Note ("AI placement: jobs -> {0} ({1}){2}" -f $h.placement.target_name, $h.placement.reason, $veto)
    }
    Note "dashboard: http://127.0.0.1:$port/ui"
    return $true
}

function Stop-Node {
    $p = Get-NodeProcs
    if ($p.Count -eq 0) { Ok 'not running'; return $true }
    $port = Get-LogPort
    if (-not $port) { $port = 3005 }
    try {
        Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$port/shutdown" -ContentType 'application/json' -Body '{}' -TimeoutSec 5 | Out-Null
        Note "stopping pid $($p[0].Id): refusing new jobs, saying goodbye to peers, finishing in-flight work"
    } catch {
        Warn "graceful stop not available on this build ($($_.Exception.Message)); stopping it"
        $p | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    $t = 0
    while ($t -lt $StopWait -and (Get-NodeProcs).Count -gt 0) {
        Start-Sleep -Seconds 1
        $t++
        if ($t % 5 -eq 0) { Note "... ${t}s" }
    }
    if ((Get-NodeProcs).Count -gt 0) {
        Warn "still running after ${StopWait}s: forcing it"
        Get-NodeProcs | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }
    Show-LogLines 'told \d+/\d+ peer|still in flight|did not finish|shutdown complete'
    if ((Get-NodeProcs).Count -gt 0) { Bad 'could not stop it'; return $false }
    Ok "stopped after ${t}s"
    return $true
}

function Start-Node {
    $p = Get-NodeProcs
    if ($p.Count -gt 0) {
        Warn "already running (pid $($p[0].Id)); to restart: .\node.cmd restart"
        Show-Status | Out-Null
        return $true
    }
    if (-not (Test-Path $Exe)) { Bad "$Exe is missing"; return $false }
    Import-NodeEnv
    if ($env:HARMONY_MOCK_TEMP) { Warn "demo mode: this node will report $($env:HARMONY_MOCK_TEMP) C until the next restart" }
    if (Test-Path $Log) { Move-Item -Force -Path $Log -Destination "$Log.1" }
    if (Test-Path $ErrLog) { Remove-Item -Force -Path $ErrLog }
    # Hidden, in its own console: closing this window does not stop the node.
    $proc = Start-Process -FilePath $Exe -WorkingDirectory $Dir -WindowStyle Hidden `
        -RedirectStandardOutput $Log -RedirectStandardError $ErrLog -PassThru
    $names = (Get-Content -Path $EnvFile -ErrorAction SilentlyContinue | Where-Object { $_ -match '^HARMONY_' } |
        ForEach-Object { ($_ -split '=')[0] }) -join ' '
    Note "starting pid $($proc.Id) ($names from harmony.env)"
    $t = 0
    while ($t -lt $StartWait * 2) {
        if ($proc.HasExited) {
            Bad 'it exited during startup:'
            Show-LogLines 'error|already running|in use|refus|panick'
            return $false
        }
        $port = Get-LogPort
        if ($port) {
            $h = Get-Health $port
            if ($h -and $h.pid -and [int]$h.pid -ne $proc.Id) { Bad "another node (pid $($h.pid)) answers on :$port"; return $false }
            if ($h -and ($h.state -eq 'ready' -or -not $h.state)) {
                Ok ("ready after {0}s" -f [int]($t / 2))
                Show-Status | Out-Null
                return $true
            }
        }
        Start-Sleep -Milliseconds 500
        $t++
    }
    Warn "not ready after ${StartWait}s (still bootstrapping?)"
    Show-Status | Out-Null
    return $true
}

# ---- keeping in step with the mesh (autosync) ----
# mesh_upgrade.sh (on the phone) has the laptop build every new version for this PC too and leave
# it in ~/harmony_win_update there: rust_p2p_node.exe, its DLLs, this script, mesh.env (the trust
# list and the advisor), BUILD (its tag), and MANIFEST + MANIFEST.sig, the phone's signature over
# all of them. This PC reaches the laptop only through its sync gate (~/.harmony/sync_gate.sh
# there): the key can read the staged files and say what was installed, nothing else. A sync
# compares BUILD with the build this PC runs; when they differ it fetches the files, has the node
# it runs now check the phone's signature and that the build was signed after the installed one,
# stops the node gracefully, installs the files, starts it again, and tells the gate once the
# node answers with the new build.

function Get-EnvValue([string]$Name) {
    if (-not (Test-Path $EnvFile)) { return $null }
    foreach ($line in Get-Content -Path $EnvFile) {
        if ($line -match "^\s*$Name=(.*)$") { return $Matches[1].Trim() }
    }
    return $null
}

function Set-EnvValue([string]$Name, [string]$Value) {
    $lines = @()
    if (Test-Path $EnvFile) { $lines = @(Get-Content -Path $EnvFile | Where-Object { $_ -notmatch "^\s*$Name=" }) }
    $lines += "$Name=$Value"
    Set-Content -Path $EnvFile -Value $lines -Encoding ASCII
}

function Test-Tag([string]$Tag) { return $Tag -match '^harmony-v\d+$' }

# A command on the laptop with this PC's sync key, never prompting. -> Ok, Lines
function Invoke-Laptop([string]$From, [string]$RemoteCommand) {
    $out = & ssh -i $SyncKey -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=8 $From $RemoteCommand 2>$null
    return [pscustomobject]@{ Ok = ($LASTEXITCODE -eq 0); Lines = @($out) }
}

# A request to the laptop's sync gate. Once the key is locked to the gate, sshd runs the gate
# whatever is asked; before that, this runs it by its path. -> Ok, Lines
function Invoke-Gate([string]$From, [string]$Request) {
    return Invoke-Laptop $From ".harmony/sync_gate.sh $Request"
}

# The id of the node that answers here, or ''.
function Get-RunningId {
    if ((Get-NodeProcs).Count -eq 0) { return '' }
    $port = Get-LogPort
    if (-not $port) { $port = 3005 }
    $h = Get-Health $port
    if ($h -and ([string]$h.node -match '^[0-9a-f]{64}$')) { return [string]$h.node }
    return ''
}

# One KEY=value from a mesh.env file, or ''.
function Get-MeshValue([string]$Path, [string]$Name) {
    if (-not (Test-Path $Path)) { return '' }
    foreach ($line in Get-Content -Path $Path) {
        if ($line -match "^\s*$Name=(.*)$") { return $Matches[1].Trim() }
    }
    return ''
}

# The settings the installed build carries in mesh.env: these keys only, well-formed values only.
# UPDATE_SIGNER is pinned once and never changed by a build. -> $true if harmony.env changed
function Use-MeshEnv {
    if (-not (Test-Path $MeshEnv)) { return $false }
    $changed = $false
    $ids = '^[0-9a-f]{64}(,[0-9a-f]{64})*$'
    foreach ($line in Get-Content -Path $MeshEnv) {
        if ($line -notmatch '^\s*([A-Z_]+)=(.*)$') { continue }
        $k = $Matches[1]
        $v = $Matches[2].Trim()
        $good = $false
        if ($k -eq 'HARMONY_TRUST_MODE') { $good = $v -match '^(strict|tofu)$' }
        elseif ($k -eq 'HARMONY_TRUST' -or $k -eq 'HARMONY_ADVISOR') { $good = $v -match $ids }
        elseif ($k -eq 'UPDATE_SIGNER') { $good = $v -match '^[0-9a-f]{64}$' }
        if (-not $good) { continue }
        if ($k -eq 'UPDATE_SIGNER') {
            if (-not (Get-EnvValue 'UPDATE_SIGNER')) { Set-EnvValue 'UPDATE_SIGNER' $v }
            continue
        }
        if ((Get-EnvValue $k) -ne $v) {
            Set-EnvValue $k $v
            $changed = $true
        }
    }
    return $changed
}

# Does this PC's key still open a shell on the laptop? -> open, locked or unreachable
function Get-KeyState([string]$From) {
    $out = @(& ssh -i $SyncKey -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=8 $From 'echo harmony-unrestricted' 2>$null)
    $code = $LASTEXITCODE
    if ($out -contains 'harmony-unrestricted') { return 'open' }
    if ($code -eq 255) { return 'unreachable' }
    return 'locked'
}

# Once per PC: make sure this PC's key reaches nothing on the laptop but the sync gate. A key that
# an older node.ps1 added opens a full shell there; asked over that shell, the gate rewrites the
# key's line (restrict-keys) so that from then on sshd runs only the gate.
function Lock-SyncKey([string]$From) {
    if ((Get-EnvValue 'SYNC_KEY_LOCKED') -eq '1') { return }
    $state = Get-KeyState $From
    if ($state -eq 'open') {
        Invoke-Gate $From 'restrict-keys' | Out-Null
        $state = Get-KeyState $From
    }
    if ($state -eq 'locked') { Set-EnvValue 'SYNC_KEY_LOCKED' '1' }
}

# The staged build, file by file (base64 over the gate), into a fresh folder.
# -> the folder, or '' with the reason in $script:FetchError
function Get-StagedBuild([string]$From) {
    $tmp = Join-Path $Dir 'update'
    if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
    New-Item -ItemType Directory -Path $tmp | Out-Null
    $list = Invoke-Gate $From 'files'
    if (-not $list.Ok) { $script:FetchError = 'the laptop did not list the staged files'; return '' }
    $n = 0
    foreach ($l in $list.Lines) {
        if ([string]$l -notmatch '^(\d+) ([A-Za-z0-9][A-Za-z0-9._-]*)$') { continue }
        $size = [int64]$Matches[1]
        $name = $Matches[2]
        if ($name.Contains('..')) { continue }
        $r = Invoke-Gate $From "get $name"
        if (-not $r.Ok) { $script:FetchError = "could not fetch $name"; return '' }
        try { $bytes = [Convert]::FromBase64String(((@($r.Lines) | ForEach-Object { [string]$_ }) -join '').Trim()) }
        catch { $script:FetchError = "$name arrived damaged"; return '' }
        if ($bytes.Length -ne $size) { $script:FetchError = "$name arrived incomplete ($($bytes.Length) of $size bytes)"; return '' }
        [System.IO.File]::WriteAllBytes((Join-Path $tmp $name), $bytes)
        $n++
    }
    if ($n -eq 0 -or -not (Test-Path (Join-Path $tmp 'rust_p2p_node.exe'))) {
        $script:FetchError = 'the staged build has no rust_p2p_node.exe'
        return ''
    }
    return $tmp
}

# Is the build in $Tmp exactly what $Signer signed? Asked of the node this PC runs now, not of the
# one about to be installed. -> 'OK build=... issued=...', 'FAIL reason', or '' when this node
# cannot check (it predates signed updates)
function Test-StagedBuild([string]$Tmp, [string]$Signer) {
    if (-not (Test-Path $Exe)) { return '' }
    $out = @(& $Exe --verify-update $Tmp --update-signer $Signer 2>$null)
    $line = @($out | ForEach-Object { [string]$_ } | Where-Object { $_ -match '^(OK|FAIL) ' }) | Select-Object -Last 1
    if ($line) { return [string]$line }
    return ''
}

# Copy files into this folder and check each copy against its source. Windows can hold a file for
# a moment after the program using it ends (an antivirus scan, the old node's image), so a copy
# that fails is tried again for 20 s. -> '' or what could not be copied
function Copy-Build($Files) {
    foreach ($f in @($Files)) {
        $dest = Join-Path $Dir $f.Name
        $want = (Get-FileHash -Algorithm SHA256 -Path $f.FullName).Hash
        $done = $false
        for ($i = 0; $i -lt 10 -and -not $done; $i++) {
            if ($i -gt 0) { Start-Sleep -Seconds 2 }
            try {
                Copy-Item -Force -Path $f.FullName -Destination $dest -ErrorAction Stop
                $done = (Get-FileHash -Algorithm SHA256 -Path $dest -ErrorAction Stop).Hash -eq $want
            } catch { $done = $false }
        }
        if (-not $done) { return "$($f.Name) could not be replaced (still in use?)" }
    }
    return ''
}

# Put the programs kept in $Prev back in place. -> what happened, in a few words
function Restore-Programs([string]$Prev) {
    $kept = @(Get-ChildItem -Path $Prev -File -ErrorAction SilentlyContinue)
    if ($kept.Count -eq 0) { return 'nothing to put back' }
    $err = Copy-Build $kept
    if ($err) { return "could not put the previous node back: $err" }
    return 'put the previous node back'
}

# Why the node that just tried to start did not: the last telling line of its logs.
function Get-StartError {
    foreach ($f in @($ErrLog, $Log)) {
        if (-not (Test-Path $f)) { continue }
        $hit = Get-Content -Path $f -Encoding UTF8 -ErrorAction SilentlyContinue |
            Select-String -Pattern 'error|panick|refus|in use|already running|failed' | Select-Object -Last 1
        if ($hit) {
            $l = (Remove-Ansi $hit.Line).Trim()
            if ($l.Length -gt 160) { $l = $l.Substring(0, 160) }
            return $l
        }
    }
    return 'its log does not say why'
}

# Record the installed build and when it was signed, once its files are in place.
function Set-Installed([string]$Want, [string]$Issued) {
    Set-Content -Path $BuildFile -Value $Want -Encoding ASCII
    if ($Issued) { Set-EnvValue 'UPDATE_ISSUED' $Issued }
}

# Check a fetched build and install it. The node and DLLs that ran until now are kept, and put
# back if the new node does not start. -> a one-line status
function Install-Staged([string]$From, [string]$Tmp, [string]$Want, [bool]$Running) {
    $signer = Get-EnvValue 'UPDATE_SIGNER'
    $pinnedNow = $false
    if (-not $signer) {
        # the first signed build this PC sees names its signer (the phone), and that one is pinned
        $signer = Get-MeshValue (Join-Path $Tmp 'mesh.env') 'UPDATE_SIGNER'
        if ($signer -notmatch '^[0-9a-f]{64}$') { return "refused ${Want}: no update signer is pinned here and the build names none" }
        Set-EnvValue 'UPDATE_SIGNER' $signer
        $pinnedNow = $true
    }
    $check = Test-StagedBuild $Tmp $signer
    $issued = ''
    if ($check -match '^OK build=(\S+) issued=(\d+)') {
        if ($Matches[1] -ne $Want) { return "refused ${Want}: the signed build is $($Matches[1])" }
        $issued = $Matches[2]
        $last = Get-EnvValue 'UPDATE_ISSUED'
        # signed before the installed build: a rollback. The same signing again is a retry.
        if ($last -and ([int64]$issued -lt [int64]$last)) {
            return "refused ${Want}: signed at $issued, before the installed build (signed at $last): a rollback? (if the phone's clock went back, delete UPDATE_ISSUED from harmony.env, then .\node.cmd sync)"
        }
    } elseif (-not $check -and $pinnedNow) {
        # the node here predates signed updates and cannot check this one: it goes in once,
        # unchecked, and the node it brings checks every build after it
        $check = 'unchecked'
    } elseif (-not $check) {
        return "refused ${Want}: the node here cannot check signatures (reinstall it with setup_windows.ps1)"
    } else {
        return "refused ${Want}: $check"
    }
    $before = Get-LocalBuild
    if (-not $before) { $before = 'the previous build' }
    if ($Running -and -not (Stop-Node)) { return "could not stop the node to install $Want" }
    $files = @(Get-ChildItem -Path $Tmp -File | Where-Object { @('BUILD', 'DEPLOYED', 'node.cmd') -notcontains $_.Name })
    # the programs that ran until now, to put back if the new ones fail
    $prev = Join-Path $Dir 'previous'
    Remove-Item -Recurse -Force -Path $prev -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $prev | Out-Null
    foreach ($f in $files) {
        $cur = Join-Path $Dir $f.Name
        if ((@('.exe', '.dll') -contains $f.Extension) -and (Test-Path $cur)) { Copy-Item -Force -Path $cur -Destination $prev }
    }
    $err = Copy-Build $files
    if ($err) {
        $back = Restore-Programs $prev
        if ($Running) { Start-Node | Out-Null }
        return "could not install ${Want}: $err; $back"
    }
    Use-MeshEnv | Out-Null
    $how = ', signature checked'
    if ($check -eq 'unchecked') { $how = ' (first signed build, unchecked: the node it replaced could not check signatures)' }
    if (-not $Running -and (Test-Path $StopFlag)) {
        Set-Installed $Want $issued
        Invoke-Gate $From "deployed $Want" | Out-Null
        return "installed $Want$how; the node stays stopped as you left it (.\node.cmd start)"
    }
    if (-not (Start-Node)) {
        # the new build does not run here: the previous node goes back, and this signing is not
        # tried again until a new one comes (its logs stay as failed-start.log, failed-start.err.log)
        $why = Get-StartError
        if (Test-Path $Log) { Copy-Item -Force -Path $Log -Destination (Join-Path $Dir 'failed-start.log') }
        if (Test-Path $ErrLog) { Copy-Item -Force -Path $ErrLog -Destination (Join-Path $Dir 'failed-start.err.log') }
        $back = Restore-Programs $prev
        if (Start-Node) { $back = "$back; $before runs again" } else { $back = "$back, but it did not start either" }
        return "$Want did not start here ($why); $back"
    }
    Set-Installed $Want $issued
    $now = Get-RunningBuild
    if ($now -ne $Want) { return "installed $Want$how; the node does not answer with it yet" }
    Invoke-Gate $From "deployed $Want $(Get-RunningId)" | Out-Null
    return "updated to $Want$how"
}

# The build the running node answers with, or '' when none answers.
function Get-RunningBuild {
    if ((Get-NodeProcs).Count -eq 0) { return '' }
    $port = Get-LogPort
    if (-not $port) { $port = 3005 }
    $h = Get-Health $port
    if ($h -and $h.build) { return [string]$h.build }
    return ''
}

# The build this PC runs: what the running node reports, else what the last sync installed.
function Get-LocalBuild {
    $b = Get-RunningBuild
    if ($b) { return $b }
    if (Test-Path $BuildFile) {
        $f = Get-Content -Path $BuildFile -TotalCount 1
        if ($f) { return ([string]$f).Trim() }
    }
    return ''
}

# Which signing of a build the laptop has staged, from its MANIFEST ("harmony-v19@1793427646"), or ''.
function Get-StagedSigning([string]$From) {
    $r = Invoke-Gate $From 'get MANIFEST'
    if (-not $r.Ok) { return '' }
    try { $text = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String(((@($r.Lines) | ForEach-Object { [string]$_ }) -join '').Trim())) }
    catch { return '' }
    $b = ''
    if ($text -match '(?m)^build (\S+)$') { $b = $Matches[1] }
    if ($b -and ($text -match '(?m)^issued (\d+)$')) { return "$b@$($Matches[1])" }
    return ''
}

# How this signing went here last time, if it is not to be tried again yet. -> that status, or ''
function Get-SkipNote([string]$Sig) {
    if (-not $Sig -or -not (Test-Path $SkipFile)) { return '' }
    $l = [string](Get-Content -Path $SkipFile -TotalCount 1)
    if (-not ($l -match '^(\S+) (\d+) (.*)$') -or $Matches[1] -ne $Sig) { return '' }
    $until = [int64]$Matches[2]
    $note = $Matches[3]
    if ($until -eq 0) { return "$note (waiting for a newly signed build; .\node.cmd sync tries this one again)" }
    if ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -ge $until) { return '' }
    return "$note (tried again at $([DateTimeOffset]::FromUnixTimeSeconds($until).LocalDateTime.ToString('HH:mm:ss')))"
}

# Remember how this signing went. A refusal or a failed start is final for it (only a new signing
# or a sync you run tries it again); anything else is retried after 2 minutes. So a build that
# cannot go in is not fetched again every round.
function Set-SkipNote([string]$Sig, [string]$Status) {
    if (-not $Sig) { return }
    $until = 0
    if ($Status -notmatch '^refused |did not start here') { $until = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 120 }
    Set-Content -Path $SkipFile -Value ('{0} {1} {2}' -f $Sig, $until, $Status) -Encoding ASCII
}

# One check against the laptop; installs a new build if there is one. $Fresh (a sync you run, or
# autosync's) also tries a build the watcher stopped retrying. -> a one-line status
function Sync-Node([bool]$Fresh = $false) {
    $from = Get-EnvValue 'SYNC_FROM'
    if (-not $from) { return 'not set up: run .\node.cmd autosync user@laptop once' }
    $extra = ''
    # a mesh.env installed by an older node.ps1 (or edited by hand) takes effect with a restart
    if (Use-MeshEnv) {
        if ((Get-NodeProcs).Count -gt 0 -and (Stop-Node)) { Start-Node | Out-Null }
        $extra = '; applied mesh.env (trust list, advisor) and restarted the node'
    }
    Lock-SyncKey $from
    $r = Invoke-Gate $from 'status'
    if (-not $r.Ok) {
        return "cannot reach the sync gate on $from with this PC's key (laptop off or asleep, or no gate yet: run mesh_upgrade.sh on the phone)$extra"
    }
    $want = ''
    $deployed = ''
    $reported = ''
    foreach ($l in $r.Lines) {
        if ($l -match '^BUILD:(\S+)') { $want = $Matches[1] }
        elseif ($l -match '^DEPLOYED:(\S+)') { $deployed = $Matches[1] }
        elseif ($l -match '^NODE:([0-9a-f]{64})') { $reported = $Matches[1] }
    }
    $running = (Get-NodeProcs).Count -gt 0
    $have = Get-LocalBuild
    if ((Test-Tag $want) -and $want -ne $have) {
        $sig = Get-StagedSigning $from
        $done = ''
        if (-not $Fresh) { $done = Get-SkipNote $sig }
        if (-not $done) {
            $tmp = Get-StagedBuild $from
            if (-not $tmp) {
                Remove-Item -Recurse -Force (Join-Path $Dir 'update') -ErrorAction SilentlyContinue
                $done = "could not copy $want from ${from}: $script:FetchError"
            } else {
                $done = Install-Staged $from $tmp $want $running
                Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
            }
            if ($done -notmatch '^(updated to|installed) ') { Set-SkipNote $sig $done }
        }
        # whatever became of the new build, the node runs unless you stopped it
        if ((Get-NodeProcs).Count -eq 0 -and -not (Test-Path $StopFlag)) { Start-Node | Out-Null }
        return "$done$extra"
    }
    if (-not $running -and -not (Test-Path $StopFlag)) { Start-Node | Out-Null }
    $now = Get-RunningBuild
    $settled = ($now -and $now -eq $want) -or (-not $now -and (Test-Path $StopFlag) -and $have -eq $want)
    if ((Test-Tag $want) -and $settled) {
        # tell the gate the build, and this node's id (mesh_upgrade.sh lists it in the trust lists)
        $nid = Get-RunningId
        if ($deployed -ne $want -or ($nid -and $nid -ne $reported)) { Invoke-Gate $from "deployed $want $nid" | Out-Null }
    }
    if (-not (Test-Tag $want)) { return "no build staged on the laptop yet$extra" }
    if ($now) { return "up to date: $now$extra" }
    return "up to date: $have (node stopped)$extra"
}

# One sync at a time on this PC: the watcher's, one you run, autosync's. A watcher's round skips
# while another sync runs; one you run waits for it. -> a one-line status
function Invoke-Sync([bool]$Fresh) {
    $lock = [System.Threading.Mutex]::new($false, 'Local\HarmonyNodeSync')
    try { $got = $lock.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $got = $true }
    if (-not $got -and -not $Fresh) { return 'another sync is running on this PC; this round skipped' }
    if (-not $got) {
        Note 'another sync is running on this PC (the watcher''s): waiting for it to finish...'
        try { $got = $lock.WaitOne(360000) } catch [System.Threading.AbandonedMutexException] { $got = $true }
        if (-not $got) { return 'another sync has run for over 6 minutes on this PC; this one did not start' }
    }
    try { return (Sync-Node $Fresh) } finally { $lock.ReleaseMutex() }
}

# Tell the laptop how the syncs here go, for mesh_upgrade.sh: one short line through the gate when
# it changes, and every 5 minutes while it does not, so the laptop also knows the watcher runs.
# Only with the key locked to the gate, which keeps the line as text and never runs it.
function Send-SyncReport([string]$Status) {
    $from = Get-EnvValue 'SYNC_FROM'
    if (-not $from -or (Get-EnvValue 'SYNC_KEY_LOCKED') -ne '1') { return }
    if ($Status -like 'cannot reach the sync gate*') { return }
    $line = (($Status -replace "[^A-Za-z0-9 .,:;()/+=_@%?!'-]", ' ') -replace '\s+', ' ').Trim()
    if ($line.Length -gt 300) { $line = $line.Substring(0, 300) }
    if (-not $line) { return }
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if (Test-Path $ReportFile) {
        $prev = [string](Get-Content -Path $ReportFile -TotalCount 1)
        if (($prev -match '^(\d+) (.*)$') -and $Matches[2] -eq $line -and ($now - [int64]$Matches[1]) -lt 300) { return }
    }
    Invoke-Gate $from "report $line" | Out-Null
    Set-Content -Path $ReportFile -Value "$now $line" -Encoding ASCII
}

function Get-WatchArgs { return '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $PSCommandPath + '" watch' }

# The watcher: one per PC. Every 15 s it runs a sync in a fresh PowerShell, so a sync always runs
# the node.ps1 on disk (including one the previous sync installed), and it adds a line to sync.log
# when the status changes. The sync reports through sync.status, not a pipe: a node it starts would
# inherit the pipe and hold it open, and the watcher would wait on it for as long as the node runs.
# Nothing that goes wrong in one round ends the watcher. It tells its syncs its own version
# ($WatchRev), so a sync run by a newer node.ps1 can say this watcher should be restarted.
function Watch-Node {
    $mutex = [System.Threading.Mutex]::new($false, 'Local\HarmonyNodeWatch')
    # a watcher that is making way for this one may need a moment to go
    try { $mine = $mutex.WaitOne(10000) } catch [System.Threading.AbandonedMutexException] { $mine = $true }
    if (-not $mine) { return }
    try { Set-Content -Path $WatchPid -Value $PID -Encoding ASCII } catch { }
    $last = ''
    $syncArgs = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" sync-status ' + $WatchRev
    while ($true) {
        try {
            Remove-Item -Force -Path $SyncStatus -ErrorAction SilentlyContinue
            $status = ''
            try {
                $p = Start-Process -FilePath $PsExe -ArgumentList $syncArgs -WindowStyle Hidden -WorkingDirectory $Dir -PassThru
                if (-not $p.WaitForExit(300000)) { $p.Kill(); $status = 'the sync took over 5 minutes and was stopped' }
            } catch { $status = "could not run the sync: $($_.Exception.Message)" }
            if (-not $status -and (Test-Path $SyncStatus)) { $status = [string](Get-Content -Path $SyncStatus -TotalCount 1) }
            if (-not $status) { $status = 'the sync did not report' }
            if ($status -ne $last) {
                Add-Content -Path $SyncLog -Value ('{0}  {1}' -f (Get-Date -Format 's'), $status) -Encoding ASCII -ErrorAction Stop
                $last = $status
            }
        } catch {
            try { Add-Content -Path $SyncLog -Value ('{0}  watcher: {1}' -f (Get-Date -Format 's'), $_.Exception.Message) -Encoding ASCII } catch { }
        }
        Start-Sleep -Seconds $WatchEvery
    }
}

# Watchers of this folder that are already running (an older node.ps1, or a stuck one).
function Get-Watchers {
    $me = [regex]::Escape($PSCommandPath)
    return @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match $me -and $_.CommandLine -match '\swatch\s*$' -and $_.ProcessId -ne $PID })
}

# Syncs a watcher started that are still running (they finish their round on their own).
function Get-SyncRuns {
    $me = [regex]::Escape($PSCommandPath)
    return @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match $me -and $_.CommandLine -match '\ssync-status(\s|$)' -and $_.ProcessId -ne $PID })
}

function Enable-AutoSync([string]$From) {
    if (-not $From) { $From = Get-EnvValue 'SYNC_FROM' }
    if (-not $From -or $From -notmatch '^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+$') {
        Bad 'usage: .\node.cmd autosync user@laptop-ip   (for example joe@192.168.1.192)'
        return $false
    }
    Set-EnvValue 'SYNC_FROM' $From
    # 1. a key of its own for the laptop, without a passphrase, so the watcher never prompts
    if (-not (Test-Path $SyncKey)) {
        New-Item -ItemType Directory -Force -Path (Split-Path $SyncKey) | Out-Null
        & ssh-keygen -q -t ed25519 -N '""' -C "harmony-sync@$env:COMPUTERNAME" -f $SyncKey | Out-Null
        if (-not (Test-Path $SyncKey)) { Bad 'ssh-keygen did not make the key'; return $false }
        Ok "made this PC's sync key ($SyncKey)"
    }
    # 2. the laptop takes it, locked to its sync gate (its password, once). The gate is installed
    #    there by mesh_upgrade.sh; the key can then read the staged build and nothing else.
    if (-not (Invoke-Gate $From 'ping').Ok) {
        $pub = (Get-Content -Path "$SyncKey.pub" -TotalCount 1).Trim()
        Note "adding this PC's key on $From, locked to its sync gate: type the laptop's password once"
        & ssh -o ConnectTimeout=8 $From ".harmony/sync_gate.sh enroll $pub" | Out-Host
        if ($LASTEXITCODE -ne 0) {
            Bad "the laptop has no sync gate yet, or refused the key: run mesh_upgrade.sh on the phone first (it installs the gate), then this again"
            return $false
        }
        if (-not (Invoke-Gate $From 'ping').Ok) { Bad "the key still does not work on $From"; return $false }
    }
    Ok "this PC reaches the sync gate on $From with its key, no password needed"
    Lock-SyncKey $From
    # 3. a running watcher keeps the node.ps1 it started with: it makes way for a new one, and a
    #    sync it started finishes first
    foreach ($w in Get-Watchers) {
        Stop-Process -Id $w.ProcessId -Force -ErrorAction SilentlyContinue
        Note "stopped the running watcher (pid $($w.ProcessId)); a new one starts below"
    }
    $t = 0
    while ((Get-SyncRuns).Count -gt 0 -and $t -lt 120) {
        if ($t -eq 0) { Note 'waiting for the sync it started to finish...' }
        Start-Sleep -Seconds 2
        $t += 2
    }
    # 4. install what the laptop has now
    Note (Invoke-Sync $true)
    # 5. the watcher: at every logon, and now
    Remove-Item -Force -Path $WatchPid -ErrorAction SilentlyContinue
    $started = $false
    try {
        $action = New-ScheduledTaskAction -Execute $PsExe -Argument (Get-WatchArgs) -WorkingDirectory $Dir
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME)
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Force `
            -Description 'Harmony mesh node: keeps it running and on the mesh build (node.ps1 watch)' -ErrorAction Stop | Out-Null
        Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        Ok "scheduled task '$TaskName' starts the watcher at every logon"
        $started = Wait-Watcher
    } catch {
        Warn "could not register the logon task ($($_.Exception.Message)); the watcher runs until you log off"
    }
    if (-not $started) {
        Start-Process -FilePath $PsExe -ArgumentList (Get-WatchArgs) -WindowStyle Hidden -WorkingDirectory $Dir | Out-Null
        $started = Wait-Watcher
    }
    # 6. and it runs
    if (-not $started) {
        Bad 'the watcher did not start: run .\node.cmd watch in this window to see why (Ctrl+C ends it)'
        return $false
    }
    $wp = ([string](Get-Content -Path $WatchPid -TotalCount 1)).Trim()
    Ok "watcher running (pid $wp): it checks the laptop every $WatchEvery s and tells it how each sync went (log: sync.log)"
    return $true
}

# Has a watcher taken its lock (it writes watch.pid then) and does it run? Waits up to 15 s.
function Wait-Watcher {
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 500
        if (Test-Path $WatchPid) {
            $wp = ([string](Get-Content -Path $WatchPid -TotalCount 1)).Trim()
            if (($wp -match '^\d+$') -and (Get-Process -Id ([int]$wp) -ErrorAction SilentlyContinue)) { return $true }
        }
    }
    return $false
}

function Show-SyncState {
    $from = Get-EnvValue 'SYNC_FROM'
    if (-not $from) { Note 'autosync: off   (.\node.cmd autosync user@laptop keeps this PC on the mesh build)'; return }
    $last = 'no check logged yet'
    if (Test-Path $SyncLog) { $last = [string](Get-Content -Path $SyncLog -Tail 1) }
    $ws = @(Get-Watchers)
    $wp = ''
    if (Test-Path $WatchPid) { $wp = ([string](Get-Content -Path $WatchPid -TotalCount 1)).Trim() }
    if ($ws.Count -eq 0) { $running = 'watcher NOT running (.\node.cmd autosync again)' }
    elseif (@($ws | Where-Object { [string]$_.ProcessId -eq $wp }).Count -gt 0) { $running = "watcher running (pid $wp, every $WatchEvery s)" }
    else { $running = "an older watcher runs (pid $($ws[0].ProcessId)): .\node.cmd autosync restarts it on this node.ps1" }
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $logon = if ($task) { "logon task $($task.State)" } else { 'no logon task, so no watcher after the next logon (.\node.cmd autosync again)' }
    Note "autosync from ${from}: $running; $logon"
    Note "last sync: $last"
    $key = if ((Get-EnvValue 'SYNC_KEY_LOCKED') -eq '1') { "key locked to the laptop's sync gate" } else { 'key not locked to the sync gate yet (the next sync does it)' }
    $signer = [string](Get-EnvValue 'UPDATE_SIGNER')
    $builds = if ($signer.Length -eq 64) { "builds must be signed by $($signer.Substring(0, 12))" } else { 'no build signer pinned yet (the first signed build pins it)' }
    $trust = [string](Get-EnvValue 'HARMONY_TRUST_MODE')
    if (-not $trust) { $trust = 'tofu' }
    Note "security: $key; $builds; trust $trust"
}

switch ($Command) {
    'start'    { Remove-Item -Force -Path $StopFlag -ErrorAction SilentlyContinue; if (-not (Start-Node)) { exit 1 } }
    'stop'     { if (Stop-Node) { Set-Content -Path $StopFlag -Value (Get-Date -Format 's') -Encoding ASCII } else { exit 1 } }
    'restart'  { Remove-Item -Force -Path $StopFlag -ErrorAction SilentlyContinue; if (Stop-Node) { if (-not (Start-Node)) { exit 1 } } else { exit 1 } }
    'status'   { $up = Show-Status; Show-SyncState; if (-not $up) { exit 1 } }
    'log'      { Get-Content -Path $Log -Tail 40 -Wait -Encoding UTF8 }
    'sync'     { $s = [string](Invoke-Sync $true); Note $s; Send-SyncReport $s }
    'sync-status' {
        # a round of the watcher's; $Arg is the watcher's version (an older watcher passes none)
        $s = [string](Invoke-Sync $false 6>$null)
        if ($Arg -ne $WatchRev) { $s += '; the watcher here is older than this node.ps1: node.cmd autosync on this PC restarts it' }
        Set-Content -Path $SyncStatus -Value $s -Encoding ASCII
        Send-SyncReport $s
    }
    'autosync' { if (-not (Enable-AutoSync $Arg)) { exit 1 } }
    'watch'    { Watch-Node }
    default    { Write-Host 'usage: .\node.cmd start|stop|restart|status|log|sync|autosync user@laptop'; exit 2 }
}
