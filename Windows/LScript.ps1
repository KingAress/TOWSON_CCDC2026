
$ErrorActionPreference = "Stop"

function Write-Log($msg) { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Err($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }


$llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"

if (-not (Test-Path $llmnrPath)) {
    New-Item -Path $llmnrPath -Force | Out-Null
}
Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWord


Write-Log "Disabling NTLMv1 (Setting LmCompatibilityLevel to 5)..."
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

Set-ItemProperty -Path $lsaPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord


Write-Log "Disabling NetBIOS over TCP/IP on all adapters..."
try {
    $nics = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
    foreach ($nic in $nics) {
        Invoke-CimMethod -InputObject $nic -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions = 2} | Out-Null
    }
} catch {
    Write-Err "Could not disable NetBIOS via CIM. You may need to do this manually in Adapter Settings."
}


Write-Log "Disabling AutoPlay (NoDriveTypeAutoRun = 255)..."
$explorerPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"

if (-not (Test-Path $explorerPath)) {
    New-Item -Path $explorerPath -Force | Out-Null
}
Set-ItemProperty -Path $explorerPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord


Write-Host ""
Write-Log "Hardening complete." 
Write-Host "Please REBOOT the server for all changes to take full effect." -ForegroundColor Cyan