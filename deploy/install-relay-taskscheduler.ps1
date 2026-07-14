# Registers the AgentMail relay to run at logon via Task Scheduler (Windows).
# The relay is decoupled from any Claude session so messages queue even when no agent is online.
#
#   pwsh -File deploy\install-relay-taskscheduler.ps1
#
# NOTE: every machine on the mesh must share the SAME bearer token. After first run, copy the
# "token" value from ~/.claude/agentmail/config.json to the other machines' config.json
# (or set AGENTMAIL_TOKEN in the task's environment).
$ErrorActionPreference = 'Stop'

$agentmail = Join-Path $env:USERPROFILE '.dotnet\tools\agentmail.exe'
if (-not (Test-Path $agentmail)) {
    throw "agentmail not found at $agentmail. Install it first: dotnet tool install --global --add-source ./nupkg AgentMail"
}

$taskName = 'AgentMail Relay'
$action   = New-ScheduledTaskAction -Execute $agentmail -Argument 'serve'
$trigger  = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero)   # no time limit — it's a daemon
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal -Force | Out-Null

Write-Host "Registered '$taskName' — runs 'agentmail serve' at logon."
Write-Host "Start it now with:  Start-ScheduledTask -TaskName '$taskName'"
Write-Host "Remove with:        Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false"
