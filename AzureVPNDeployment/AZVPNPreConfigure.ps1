## Pre-requisted to install. Rah 
# Define registry paths and property names
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock"
$devModeProperty = "AllowDevelopmentWithoutDevLicense"
$sideloadProperty = "AllowAllTrustedApps"

# Check Developer Mode status
$devModeEnabled = (Get-ItemProperty -Path $registryPath -Name $devModeProperty -ErrorAction SilentlyContinue).$devModeProperty

# Enable Developer Mode if not enabled
if ($devModeEnabled -ne 1) {
    if (-not (Test-Path -Path $registryPath)) {
        New-Item -Path $registryPath -ItemType Directory -Force
    }
    New-ItemProperty -Path $registryPath -Name $devModeProperty -PropertyType DWORD -Value 1 -Force
    Write-Output "Developer Mode has been enabled."
} else {
    Write-Output "Developer Mode is already enabled."
}

# Check Sideload Apps status
$sideloadEnabled = (Get-ItemProperty -Path $registryPath -Name $sideloadProperty -ErrorAction SilentlyContinue).$sideloadProperty

# Enable Sideload Apps if not enabled
if ($sideloadEnabled -ne 1) {
    if (-not (Test-Path -Path $registryPath)) {
        New-Item -Path $registryPath -ItemType Directory -Force
    }
    New-ItemProperty -Path $registryPath -Name $sideloadProperty -PropertyType DWORD -Value 1 -Force
    Write-Output "Sideloading apps has been enabled."
} else {
    Write-Output "Sideloading apps is already enabled."
}
