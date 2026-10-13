<#
.SYNOPSIS
    TGAM-SOC Windows Telemetry Agent Controller
.DESCRIPTION
    Controls the local Windows Telemetry collection and detection pipeline.
    Commands: start | stop | status | run
#>

[CmdletBinding()]
param (
    [Parameter(Position = 0, Mandatory = $false)]
    [ValidateSet("start", "stop", "status", "run", "help")]
    [string]$Command = "status"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$PidFile = Join-Path $ScriptDir ".agent.pid"
$LogFile = Join-Path $ScriptDir "agent.log"
$ErrFile = Join-Path $ScriptDir "agent.err.log"
$MainPy = Join-Path $ScriptDir "main.py"

function Get-AgentProcess {
    if (Test-Path $PidFile) {
        $rawPid = (Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($rawPid) {
            $trimmedPid = $rawPid.Trim()
            if ($trimmedPid -match '^\d+$') {
                $p = Get-Process -Id ([int]$trimmedPid) -ErrorAction SilentlyContinue
                if ($p -and ($p.ProcessName -match "python")) {
                    return $p
                }
            }
        }
    }
    return $null
}

function Get-AgentInfo {
    $info = @{
        AgentId = "Unknown"
        Hostname = $env:COMPUTERNAME
        SocUrl = "http://127.0.0.1:8000"
        PendingOutbox = 0
        DataDir = ""
    }

    # Query Python config & outbox state safely via one-liner
    $pyCmd = @"
import json, os, sqlite3
try:
    from config.settings import config
    outbox_count = 0
    if os.path.exists(config.outbox_db_path):
        conn = sqlite3.connect(config.outbox_db_path)
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM outbox WHERE status='pending'")
        outbox_count = cur.fetchone()[0]
        conn.close()
    
    agent_id = 'Unknown'
    id_file = os.path.join(config.data_dir, 'agent_identity.json')
    if os.path.exists(id_file):
        with open(id_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            agent_id = data.get('agent_id', 'Unknown')
    
    print(json.dumps({
        'agent_id': agent_id,
        'soc_url': config.soc_api_url,
        'pending_outbox': outbox_count,
        'data_dir': config.data_dir
    }))
except Exception as e:
    print(json.dumps({'error': str(e)}))
"@
    try {
        $jsonOut = & python -c $pyCmd 2>$null
        if ($jsonOut) {
            $parsed = $jsonOut | ConvertFrom-Json
            if ($parsed.agent_id) { $info.AgentId = $parsed.agent_id }
            if ($parsed.soc_url) { $info.SocUrl = $parsed.soc_url }
            if ($parsed.pending_outbox -ne $null) { $info.PendingOutbox = $parsed.pending_outbox }
            if ($parsed.data_dir) { $info.DataDir = $parsed.data_dir }
        }
    } catch {}
    return $info
}

switch ($Command) {
    "start" {
        $existing = Get-AgentProcess
        if ($existing) {
            Write-Host "[ALREADY RUNNING] Windows Telemetry Agent is already active (PID: $($existing.Id))." -ForegroundColor Yellow
            exit 0
        }

        # Clear stale PID file if present
        if (Test-Path $PidFile) {
            Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
        }

        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Write-Host "[NOTICE] Live Windows Security event collection requires Administrator rights." -ForegroundColor Yellow
            Write-Host "         Run PowerShell as Administrator ('Run as Administrator') for live Event 4625 ingestion." -ForegroundColor Yellow
        }

        Write-Host "Starting Windows Telemetry Agent in background..." -ForegroundColor Cyan
        
        # Start background process
        $proc = Start-Process -FilePath "python" `
            -ArgumentList "main.py" `
            -WorkingDirectory $ScriptDir `
            -RedirectStandardOutput $LogFile `
            -RedirectStandardError $ErrFile `
            -WindowStyle Hidden `
            -PassThru

        # Persist PID
        $proc.Id | Out-File -FilePath $PidFile -Encoding ascii -Force

        # Wait briefly and verify process didn't exit on startup error
        Start-Sleep -Milliseconds 800
        if ($proc.HasExited) {
            Write-Host "[ERROR] Agent process exited immediately (ExitCode: $($proc.ExitCode))." -ForegroundColor Red
            if ((Test-Path $ErrFile) -and ((Get-Item $ErrFile).Length -gt 0)) {
                Write-Host "Recent Error Output ($ErrFile):" -ForegroundColor Red
                Get-Content $ErrFile -Tail 15
            } elseif (Test-Path $LogFile) {
                Write-Host "Recent Log Output ($LogFile):" -ForegroundColor Red
                Get-Content $LogFile -Tail 15
            }
            Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
            exit 1
        }

        $info = Get-AgentInfo
        Write-Host "[SUCCESS] Windows Telemetry Agent started." -ForegroundColor Green
        Write-Host "  PID:               $($proc.Id)" -ForegroundColor Gray
        Write-Host "  Agent ID:          $($info.AgentId)" -ForegroundColor Gray
        Write-Host "  Central SOC:       $($info.SocUrl)" -ForegroundColor Gray
        Write-Host "  Log File:          $LogFile" -ForegroundColor Gray
    }

    "stop" {
        $proc = Get-AgentProcess
        if (-not $proc) {
            Write-Host "[NOT RUNNING] Windows Telemetry Agent is not currently running." -ForegroundColor Yellow
            if (Test-Path $PidFile) {
                Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
            }
            exit 0
        }

        $targetPid = $proc.Id
        Write-Host "Stopping Windows Telemetry Agent (PID: $targetPid)..." -ForegroundColor Cyan

        try {
            Stop-Process -Id $targetPid -ErrorAction SilentlyContinue
            $proc.WaitForExit(4000)
        } catch {}

        if (Test-Path $PidFile) {
            Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
        }

        Write-Host "[SUCCESS] Windows Telemetry Agent (PID: $targetPid) stopped cleanly." -ForegroundColor Green
    }

    "status" {
        $proc = Get-AgentProcess
        $info = Get-AgentInfo

        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "TGAM-SOC Windows Telemetry Agent Status" -ForegroundColor Cyan
        Write-Host "==================================================" -ForegroundColor Cyan

        if ($proc) {
            Write-Host "  Process State:     " -NoNewline
            Write-Host "RUNNING" -ForegroundColor Green
            Write-Host "  PID:               $($proc.Id)"
            Write-Host "  Memory (MB):       $([math]::Round($proc.WorkingSet64 / 1MB, 2))"
            Write-Host "  Start Time:        $($proc.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
        } else {
            Write-Host "  Process State:     " -NoNewline
            Write-Host "STOPPED" -ForegroundColor Red
        }

        Write-Host "  Agent ID:          $($info.AgentId)"
        Write-Host "  Hostname:          $($info.Hostname)"
        Write-Host "  Operating System:  Windows"
        Write-Host "  Central SOC URL:   $($info.SocUrl)"
        Write-Host "  Pending Outbox:    $($info.PendingOutbox) events"
        Write-Host "  Log Path:          $LogFile"

        if (Test-Path $LogFile) {
            Write-Host "`nRecent Log Entries:" -ForegroundColor DarkGray
            Get-Content $LogFile -Tail 5 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        }
        Write-Host "==================================================" -ForegroundColor Cyan
    }

    "run" {
        $existing = Get-AgentProcess
        if ($existing) {
            Write-Host "[WARNING] A background agent is already running (PID: $($existing.Id))." -ForegroundColor Yellow
            Write-Host "Stopping the background agent before interactive run is recommended." -ForegroundColor Yellow
        }
        Write-Host "Running Windows Telemetry Agent in foreground (Ctrl+C to terminate)..." -ForegroundColor Cyan
        & python (Join-Path $ScriptDir "main.py")
    }

    default {
        Write-Host "Usage: .\agent.ps1 {start | stop | status | run}" -ForegroundColor Yellow
        exit 1
    }
}
