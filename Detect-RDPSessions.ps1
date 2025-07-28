[CmdletBinding()]
param(
  [int]$IdleThresholdMinutes = 30,
  [string]$LogPath = "$env:TEMP\Detect-RDPSessions.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$LogMaxKB = 100
$LogKeep = 5
$runStart = Get-Date

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
  Add-Content -Path $LogPath -Value $line
}

function Rotate-Log {
  if (Test-Path $LogPath -PathType Leaf) {
    if ((Get-Item $LogPath).Length / 1KB -gt $LogMaxKB) {
      for ($i = $LogKeep - 1; $i -ge 0; $i--) {
        $old = "$LogPath.$i"
        $new = "$LogPath." + ($i + 1)
        if (Test-Path $old) { Rename-Item $old $new -Force }
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

Rotate-Log
Write-Log "=== SCRIPT START : Detect RDP Sessions ==="

try {
  $quserOutput = quser 2>$null
  $Sessions = @()
  if ($quserOutput) {
    foreach ($line in $quserOutput[1..($quserOutput.Count - 1)]) {
      $parts = $line -split '\s+', 6
      if ($parts.Count -ge 6) {
        $session = [PSCustomObject]@{
          user = $parts[0]
          session_id = $parts[2]
          state = $parts[3]
          idle_time = $parts[4]
          logon_time = $parts[5]
          flagged_reasons = @()
        }
        if ($session.idle_time -match '(\d+):' -and ([int]$matches[1] -ge $IdleThresholdMinutes)) {
          $session.flagged_reasons += "Idle for $($session.idle_time)"
          Write-Log "Flagged: $($session.user) idle $($session.idle_time)" 'WARN'
        }
        $Sessions += $session
      }
    }
  }

  $timestamp = (Get-Date).ToString('o')

  $Report = [PSCustomObject]@{
    host             = $HostName
    timestamp        = $timestamp
    action           = "detect_rdp_sessions"
    idle_threshold_m = $IdleThresholdMinutes
    total_sessions   = $Sessions.Count
    sessions         = $Sessions
    flagged_sessions = $Sessions | Where-Object { $_.flagged_reasons.Count -gt 0 }
  }
  $json = $Report | ConvertTo-Json -Depth 5 -Compress
  $tempFile = "$env:TEMP\arlog.tmp"
  Set-Content -Path $tempFile -Value $json -Encoding ascii -Force

  try {
    Move-Item -Path $tempFile -Destination $ARLog -Force
    Write-Log "Log file replaced at $ARLog"
  } catch {
    Move-Item -Path $tempFile -Destination "$ARLog.new" -Force
    Write-Log "Log locked, wrote results to $ARLog.new" 'WARN'
  }
  Write-Host "`n=== Active RDP Session Report ==="
  Write-Host "Host: $HostName"
  Write-Host "Total Sessions Found: $($Sessions.Count)"
  Write-Host "Idle Sessions (>$IdleThresholdMinutes min): $($Report.flagged_sessions.Count)`n"

  if ($Sessions.Count -gt 0) {
    $Sessions | Select-Object user, session_id, state, idle_time, logon_time | Format-Table -AutoSize
  } else {
    Write-Host "No active RDP sessions."
  }
} catch {
  Write-Log $_.Exception.Message 'ERROR'
  $errorObj = [PSCustomObject]@{
    timestamp = (Get-Date).ToString('o')
    host      = $HostName
    action    = "detect_rdp_sessions"
    status    = "error"
    error     = $_.Exception.Message
  }
  $json = $errorObj | ConvertTo-Json -Compress
  $tempFile = "$env:TEMP\arlog.tmp"
  Set-Content -Path $tempFile -Value $json -Encoding ascii -Force
  try {
    Move-Item -Path $tempFile -Destination $ARLog -Force
  } catch {
    Move-Item -Path $tempFile -Destination "$ARLog.new" -Force
  }
} finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
