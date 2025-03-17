# Create a new local user named "admin" without a password
$username = "admin"
$password = ""
New-LocalUser -Name $username -Password $password -FullName "Admin User" -Description "Local Admin User"
Net User "admin" "" /add
net localgroup administrators admin /add
net localgroup admin administrators /add
# Add the new user to the Administrators group
Add-LocalGroupMember -Group "Administrators" -Member $username

# Remove the defaultuser0 account
net user defaultuser0 /delete

# Set the new user as the default user for auto-login
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /t REG_SZ /d $username /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoLogonCount /t REG_DWORD /d 1 /f

# Remove OOBE
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v LaunchUserOOBE /f

# Modify OOBE settings
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"
$registryPath2 = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"

$Name1 = "DisablePrivacyExperience"
$Name2 = "DisableVoice"
$Name3 = "PrivacyConsentStatus"
$Name4 = "Protectyourpc"
$Name5 = "HideEULAPage"
$Name6 = "EnableFirstLogonAnimation"

New-ItemProperty -Path $registryPath -Name $Name1 -Value 1 -PropertyType DWord -Force
New-ItemProperty -Path $registryPath -Name $Name2 -Value 1 -PropertyType DWord -Force
New-ItemProperty -Path $registryPath -Name $Name3 -Value 1 -PropertyType DWord -Force
New-ItemProperty -Path $registryPath -Name $Name4 -Value 3 -PropertyType DWord -Force
New-ItemProperty -Path $registryPath -Name $Name5 -Value 1 -PropertyType DWord -Force
New-ItemProperty -Path $registryPath2 -Name $Name6 -Value 1 -PropertyType DWord -Force

# Define the path to the Autopilot configuration files
$autopilotPath = "C:\Windows\Provisioning\Autopilot"

# Define the registry paths for Autopilot settings
$autopilotRegistryPath1 = "HKLM:\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot"
$autopilotRegistryPath2 = "HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotPolicyCache"
$autopilotRegistryPath3 = "HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotSettings"

# Check if the registry paths exist and delete them
if (Test-Path -Path $autopilotRegistryPath1) {
    Remove-Item -Path $autopilotRegistryPath1 -Force -Recurse
    Write-Host "Autopilot diagnostics registry key has been deleted."
} else {
    Write-Host "The specified Autopilot diagnostics registry key does not exist."
}

if (Test-Path -Path $autopilotRegistryPath2) {
    Remove-Item -Path $autopilotRegistryPath2 -Force -Recurse
    Write-Host "Autopilot policy cache registry key has been deleted."
} else {
    Write-Host "The specified Autopilot policy cache registry key does not exist."
}

if (Test-Path -Path $autopilotRegistryPath3) {
    Remove-Item -Path $autopilotRegistryPath3 -Force -Recurse
    Write-Host "Autopilot settings registry key has been deleted."
} else {
    Write-Host "The specified Autopilot settings registry key does not exist."
}
