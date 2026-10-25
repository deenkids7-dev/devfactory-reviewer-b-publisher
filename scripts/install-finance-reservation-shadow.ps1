# Install a local NO-SPEND shadow process at user logon, separate from DevFactory Runner.
# Not an independently trusted financial authority; requires future admin service-account cutover.
$ErrorActionPreference='Stop'
$task='DevFactory-Finance-Ledger-Shadow'
$target=Join-Path $env:LOCALAPPDATA 'DevFactory\FinanceReservation'
$source=Join-Path $PSScriptRoot '..\service'
$launcher=Join-Path $PSScriptRoot 'finance-reservation-shadow-start.ps1'
if(Test-Path -LiteralPath $target) { throw 'FINANCE_SHADOW_ALREADY_INSTALLED_OR_PARTIAL' }
if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) { throw 'FINANCE_SHADOW_TASK_ALREADY_EXISTS' }
if(Get-NetTCPConnection -LocalPort 47881 -State Listen -ErrorAction SilentlyContinue) { throw 'FINANCE_SHADOW_PORT_IN_USE' }
foreach($name in @('finance-reservation-ledger.mjs','finance-reservation-server.mjs')) {
  if(-not (Test-Path -LiteralPath (Join-Path $source $name) -PathType Leaf)) {
    throw ('MISSING_SOURCE_'+$name)
  }
}
if(-not (Test-Path -LiteralPath $launcher -PathType Leaf)) { throw 'LAUNCHER_MISSING' }
$dirs=@($target,(Join-Path $target 'app'),(Join-Path $target 'secrets'),(Join-Path $target 'state'))
foreach($dir in $dirs) { [void][IO.Directory]::CreateDirectory($dir) }
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$rule=[string]::Concat('*',$sid,':(OI)(CI)F')
& icacls.exe $target '/inheritance:r' '/grant:r' $rule '*S-1-5-18:(OI)(CI)F' '/T' | Out-Null
if($LASTEXITCODE -ne 0) { throw 'FINANCE_SHADOW_ACL_FAILED' }
foreach($name in @('finance-reservation-ledger.mjs','finance-reservation-server.mjs')) {
  Copy-Item -LiteralPath (Join-Path $source $name) -Destination (Join-Path (Join-Path $target 'app') $name)
}
Copy-Item -LiteralPath $launcher -Destination (Join-Path (Join-Path $target 'app') 'finance-reservation-shadow-start.ps1')
function New-Token() {
  $bytes=New-Object 'System.Byte[]' 32
  $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
  return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}
foreach($role in @('client','admin')) {
  $secret=New-Token
  $secure=ConvertTo-SecureString -String $secret -AsPlainText -Force
  $cipher=ConvertFrom-SecureString -SecureString $secure
  [IO.File]::WriteAllText((Join-Path (Join-Path $target 'secrets') ($role+'.dpapi')),$cipher,[Text.UTF8Encoding]::new($false))
  $secret=$null
}
$action=New-ScheduledTaskAction -Execute (Join-Path $PSHOME 'powershell.exe') -Argument ('-NoProfile -NonInteractive -WindowStyle Hidden -File "'+(Join-Path (Join-Path $target 'app') 'finance-reservation-shadow-start.ps1')+'"')
$trigger=New-ScheduledTaskTrigger -AtLogOn -User ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
$principal=New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 0) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'NO-SPEND finance ledger shadow, localhost only; never grants Runner permission' | Out-Null
Start-ScheduledTask -TaskName $task
Write-Output 'FINANCE_SHADOW_REGISTERED_AND_START_REQUESTED'
Write-Output 'FINANCE_SHADOW_PROVIDER_SPEND_DENIED'
