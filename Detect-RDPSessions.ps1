[CmdletBinding()]
param(
  [int]$IdleThresholdMinutes = 30,
  [string]$LogPath = "$env:TEMP\Detect-RDPSessions.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName  = $env:COMPUTERNAME
$LogMaxKB  = 100
$LogKeep   = 5
$runStart  = Get-Date

function Write-Log {
  param([string]$Message, [ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level = 'INFO')
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line = "[$ts][$Level] $Message"
  switch ($Level) {
    'ERROR' { Write-Host $line -ForegroundColor Red }
    'WARN'  { Write-Host $line -ForegroundColor Yellow }
    'DEBUG' { if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) { Write-Verbose $line } }
    default { Write-Host $line }
  }
  Add-Content -Path $LogPath -Value $line -Encoding utf8
}

function Rotate-Log {
  if (Test-Path $LogPath -PathType Leaf) {
    if ((Get-Item $LogPath).Length / 1KB -gt $LogMaxKB) {
      for ($i = $LogKeep - 1; $i -ge 0; $i--) {
        $old = "$LogPath.$i"; $new = "$LogPath." + ($i + 1)
        if (Test-Path $old) { Rename-Item $old $new -Force }
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function To-ISO8601 {
  param($dt)
  if ($dt -and $dt -is [datetime] -and $dt.Year -gt 1900) { $dt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
}

function New-NdjsonLine { param([hashtable]$Data) ($Data | ConvertTo-Json -Compress -Depth 7) }

function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp = Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
  $payload = ($JsonLines -join [Environment]::NewLine) + [Environment]::NewLine
  Set-Content -Path $tmp -Value $payload -Encoding ascii -Force
  try { Move-Item -Path $tmp -Destination $Path -Force } catch { Move-Item -Path $tmp -Destination ($Path + '.new') -Force }
}

function Parse-IdleMinutes {
  param([string]$IdleStr)
  if ([string]::IsNullOrWhiteSpace($IdleStr)) { return 0 }
  $s = $IdleStr.Trim()
  if ($s -in @('none','.')) { return 0 }
  if ($s -match '^(\d+)\+(\d+):(\d+)$') { return ([int]$matches[1])*1440 + ([int]$matches[2])*60 + ([int]$matches[3]) }
  if ($s -match '^(\d+):(\d+)$')       { return ([int]$matches[1])*60 + ([int]$matches[2]) }
  if ($s -match '^(\d+)\+$')           { return ([int]$matches[1])*1440 } 
  if ($s -match '^\d+$')               { return [int]$s }                 
  return 0
}

Rotate-Log
Write-Log "=== SCRIPT START : Detect RDP Sessions (host=$HostName, threshold=${IdleThresholdMinutes}m) ==="

$tsNow = To-ISO8601 (Get-Date)

try {
  $quserOutput = quser 2>$null
  $quserExit   = $LASTEXITCODE

  $Sessions = @()

  if ($quserOutput -and $quserOutput.Count -ge 2) {
    foreach ($raw in $quserOutput[1..($quserOutput.Count - 1)]) {
      if ([string]::IsNullOrWhiteSpace($raw)) { continue }
      $parts = $raw -replace '\s{2,}', ' ' -split '\s+', 6
      if ($parts.Count -ge 6) {
        $user   = $parts[0]
        $sid    = $parts[2]
        $state  = $parts[3]
        $idle   = $parts[4]
        $logon  = $parts[5]

        $idleMin = Parse-IdleMinutes $idle
        $flagged = $idleMin -ge $IdleThresholdMinutes
        $reasons = @()
        if ($flagged) {
          $reasons += "idle_${idleMin}m_ge_threshold_${IdleThresholdMinutes}m"
          Write-Log ("Flagged: user={0} sid={1} state={2} idle={3} ({4}m)" -f $user,$sid,$state,$idle,$idleMin) 'WARN'
        }

        $Sessions += [pscustomobject]@{
          user            = $user
          session_id      = $sid
          state           = $state
          idle_time       = $idle
          idle_minutes    = $idleMin
          logon_time      = $logon
          flagged         = $flagged
          flagged_reasons = $reasons
        }
      }
    }
  } else {
    Write-Log "No quser output or only header returned." 'WARN'
  }

  $flaggedSessions = $Sessions | Where-Object { $_.flagged }
  $countAll        = ($Sessions | Measure-Object).Count
  $countFlagged    = ($flaggedSessions | Measure-Object).Count

  $lines = New-Object System.Collections.ArrayList

  [void]$lines.Add( (New-NdjsonLine @{
    timestamp      = $tsNow
    host           = $HostName
    action         = 'detect_rdp_sessions'
    copilot_action = $true
    item           = 'verify_source'
    description    = 'RDP/Terminal Services sessions parsed from quser output'
    source         = 'quser'
    exit_code      = $quserExit
    parsed_rows    = $countAll
  }) )

  foreach ($s in $Sessions) {
    [void]$lines.Add( (New-NdjsonLine @{
      timestamp      = $tsNow
      host           = $HostName
      action         = 'detect_rdp_sessions'
      copilot_action = $true
      item           = 'session'
      description    = "User '$($s.user)' session $($s.session_id) state=$($s.state); idle=$($s.idle_time) ($($s.idle_minutes)m); flagged=$($s.flagged)"
      user           = $s.user
      session_id     = $s.session_id
      state          = $s.state
      idle_time      = $s.idle_time
      idle_minutes   = $s.idle_minutes
      logon_time     = $s.logon_time
      flagged        = $s.flagged
      reasons        = $s.flagged_reasons
      threshold_m    = $IdleThresholdMinutes
    }) )
  }

  if ($countAll -eq 0) {
    [void]$lines.Add( (New-NdjsonLine @{
      timestamp      = $tsNow
      host           = $HostName
      action         = 'detect_rdp_sessions'
      copilot_action = $true
      item           = 'status'
      status         = 'no_results'
      description    = 'No active sessions parsed from quser'
    }) )
  }

  # summary first
  $summary = New-NdjsonLine @{
    timestamp        = $tsNow
    host             = $HostName
    action           = 'detect_rdp_sessions'
    copilot_action   = $true
    item             = 'summary'
    description      = 'Run summary and counts'
    idle_threshold_m = $IdleThresholdMinutes
    total_sessions   = $countAll
    flagged_sessions = $countFlagged
    duration_s       = [math]::Round(((Get-Date)-$runStart).TotalSeconds,1)
  }
  $lines = ,$summary + $lines

  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log ("Wrote {0} NDJSON record(s) to {1}" -f $lines.Count, $ARLog) 'INFO'

  Write-Host "`n=== Active RDP Session Report ==="
  Write-Host "Host: $HostName"
  Write-Host "Total Sessions Found: $countAll"
  Write-Host "Idle Sessions (>= $IdleThresholdMinutes min): $countFlagged`n"
  if ($countAll -gt 0) {
    $Sessions | Select-Object user, session_id, state, idle_time, logon_time | Format-Table -AutoSize
  } else {
    Write-Host "No active RDP sessions."
  }
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $err = New-NdjsonLine @{
    timestamp      = To-ISO8601 (Get-Date)
    host           = $HostName
    action         = 'detect_rdp_sessions'
    copilot_action = $true
    item           = 'error'
    description    = 'Unhandled error'
    error          = $_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @($err) -Path $ARLog
  Write-Log "Error NDJSON written." 'INFO'
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
