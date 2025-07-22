# PowerShell Detect RDP Sessions Template

This repository provides a template for PowerShell-based active response scripts for security automation and incident response. The template ensures consistent logging, error handling, and execution flow for detecting active and idle RDP sessions on Windows systems.

---

## Overview

The `Detect-RDPSessions.ps1` script enumerates all active Remote Desktop Protocol (RDP) sessions, flags those that have been idle for a configurable threshold, and logs all actions, results, and errors in both a script log and an active-response log. This makes it suitable for integration with SOAR platforms, SIEMs, and incident response workflows.

---

## Template Structure

### Core Components

- **Parameter Definitions**: Configurable script parameters
- **Logging Framework**: Consistent logging with timestamps and rotation
- **Flagging Logic**: Identifies idle or suspicious RDP sessions
- **JSON Output**: Standardized response format
- **Execution Timing**: Performance monitoring

---

## How Scripts Are Invoked

### Command Line Execution

```powershell
.\Detect-RDPSessions.ps1 [-IdleThresholdMinutes <int>] [-LogPath <string>] [-ARLog <string>]
```

### Parameters

| Parameter            | Type   | Default Value                                                    | Description                                  |
|----------------------|--------|------------------------------------------------------------------|----------------------------------------------|
| `IdleThresholdMinutes` | int  | `30`                                                             | Idle time threshold (minutes) for flagging   |
| `LogPath`            | string | `$env:TEMP\Detect-RDPSessions.log`                               | Path for execution logs                      |
| `ARLog`              | string | `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log` | Path for active response JSON output         |

---

### Example Invocations

```powershell
# Basic execution with default parameters
.\Detect-RDPSessions.ps1

# Custom idle threshold and log path
.\Detect-RDPSessions.ps1 -IdleThresholdMinutes 60 -LogPath "C:\Logs\RDP.log"

# Integration with OSSEC/Wazuh active response
.\Detect-RDPSessions.ps1 -ARLog "C:\ossec\active-responses.log"
```

---

## Template Functions

### `Write-Log`
**Purpose**: Standardized logging with severity levels and console output.

**Parameters**:
- `Message` (string): The log message
- `Level` (ValidateSet): Log level - 'INFO', 'WARN', 'ERROR', 'DEBUG'

**Features**:
- Timestamped output
- Color-coded console output
- File logging
- Verbose/debug support

**Usage**:
```powershell
Write-Log "Flagged: $($session.user) idle $($session.idle_time)" 'WARN'
Write-Log "JSON reports (full + flagged) appended to $ARLog" 'INFO'
```

---

### `Rotate-Log`
**Purpose**: Manages log file size and rotation.

**Features**:
- Monitors log file size (default: 100KB)
- Maintains a configurable number of backups (default: 5)
- Rotates logs automatically

**Configuration Variables**:
- `$LogMaxKB`: Max log file size in KB
- `$LogKeep`: Number of rotated logs to retain

---

## Script Execution Flow

1. **Initialization**
   - Parameter validation and assignment
   - Error action preference
   - Log rotation
   - Start time logging

2. **Execution**
   - Enumerates active RDP sessions using `quser`
   - Flags sessions idle for more than the threshold
   - Logs findings

3. **Completion**
   - Outputs full inventory and flagged sessions as JSON to the active response log
   - Logs script end and duration
   - Displays summary in console

4. **Error Handling**
   - Catches and logs exceptions
   - Outputs error details as JSON

---

## JSON Output Format

### Full Report Example

```json
{
  "host": "HOSTNAME",
  "timestamp": "2025-07-22T10:30:45.123Z",
  "action": "detect_rdp_sessions",
  "session_count": 3,
  "sessions": [
    {
      "user": "alice",
      "session_id": "2",
      "state": "Active",
      "idle_time": "00:45",
      "logon_time": "7/22/2025 09:00",
      "flagged_reasons": []
    }
  ]
}
```

### Flagged Sessions Example

```json
{
  "host": "HOSTNAME",
  "timestamp": "2025-07-22T10:30:45.123Z",
  "action": "detect_rdp_sessions_flagged",
  "flagged_count": 1,
  "flagged_sessions": [
    {
      "user": "bob",
      "session_id": "3",
      "state": "Active",
      "idle_time": "01:15",
      "logon_time": "7/22/2025 08:00",
      "flagged_reasons": ["Idle for 01:15"]
    }
  ]
}
```

### Error Example

```json
{
  "timestamp": "2025-07-22T10:31:10.456Z",
  "host": "HOSTNAME",
  "action": "detect_rdp_sessions",
  "status": "error",
  "error": "Access is denied"
}
```

---

## Implementation Guidelines

1. Use the provided logging and error handling functions.
2. Customize the flagging logic as needed for your environment.
3. Ensure JSON output matches your SOAR/SIEM requirements.
4. Test thoroughly in a non-production environment.

---

## Security Considerations

- Run with the minimum required privileges.
- Validate all input parameters.
- Secure log files and output locations.
- Monitor for errors and failed inventory.

---

## Troubleshooting

- **Permission Errors**: Run as Administrator.
- **No RDP Sessions**: Ensure RDP is enabled and sessions are active.
- **Log Output**: Check file permissions and disk space.

---

## License

This template is provided as-is for security automation and
