# Export the settings the Windows baseline checks, as JSON. Run as admin on the target host.
$s = @{}
$s.SMB1Protocol = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State.ToString()
$s.EnableMulticast = [string](Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue).EnableMulticast
$na = net accounts
$s.LockoutBadCount = (($na | Select-String 'Lockout threshold') -split ':')[1].Trim()
$s.MinimumPasswordLength = (($na | Select-String 'Minimum password length') -split ':')[1].Trim()
$s.LAPSEnabled = [string][int]((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -ErrorAction SilentlyContinue) -ne $null)
$s.AuditLogon = ((auditpol /get /subcategory:"Logon" | Select-Object -Last 1) -split '\s{2,}')[-1].Trim()
$s.AuditProcessCreation = ((auditpol /get /subcategory:"Process Creation" | Select-Object -Last 1) -split '\s{2,}')[-1].Trim()
$s.EnableLUA = [string](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA
$s.BitLockerOS = (Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus.ToString()
$s.DefenderRealtime = [string][int](Get-MpComputerStatus).RealTimeProtectionEnabled
$s | ConvertTo-Json | Out-File "$env:COMPUTERNAME.json" -Encoding utf8
