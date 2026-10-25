# Elevation wrapper: publish only sanitized status, never credentials.
$ErrorActionPreference='Stop'
$installer=Join-Path $PSScriptRoot 'install-finance-reservation-authority.ps1'
$report=Join-Path $env:LOCALAPPDATA 'DevFactory\FinanceReservation\authority-cutover-result.txt'
try{
  $output=@(& $installer -ResumePartial 2>&1 | ForEach-Object { $_.ToString() })
  [IO.File]::WriteAllText($report,($output -join [Environment]::NewLine),[Text.UTF8Encoding]::new($false))
}catch{
  $message='FINANCE_AUTHORITY_FAILED: '+$_.Exception.Message
  [IO.File]::WriteAllText($report,$message,[Text.UTF8Encoding]::new($false))
  exit 1
}
