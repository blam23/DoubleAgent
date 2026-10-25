$runner = Join-Path $PSScriptRoot 'run-doubleagent-hidden.vbs'
$action = New-ScheduledTaskAction -Execute "$env:WINDIR\System32\wscript.exe" -Argument "//B //NoLogo `"$runner`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName 'DoubleAgent' -Action $action -Trigger $trigger -Settings $settings -Description 'Monitor agent instruction files' -Force
