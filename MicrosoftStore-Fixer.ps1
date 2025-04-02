# PLEASE READ BEFORE YOU RUN THIS
# THIS CODE WAS WRITTEN DUE TO STRANGE ISSUES WITH MSSTORE SUCH AS 0x80073cf3 WITHIN OUR DOMAIN/CORPORATE ENV. THIS CODE RESOLVED IT HOWEVER MAY NOT RESOLVE YOURS

# Function to create or update registry key
function Set-RegistryKey {
    param (
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWORD"
    )

    if (!(Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    if (!(Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
        Write-Host "Added: $Path\$Name"
    } else {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value
        Write-Host "Updated: $Path\$Name"
    }
}

# SCHANNEL Protocol Settings
$protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3")
$endpoints = @("Client", "Server")
$properties = @("Enabled", "DisabledByDefault")

foreach ($protocol in $protocols) {
    foreach ($endpoint in $endpoints) {
        foreach ($property in $properties) {
            $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\$endpoint"
            $value = if ($protocol -eq "TLS 1.2") { if ($property -eq "Enabled") { 16777215 } else { 0 } } else { 0 }
            Set-RegistryKey -Path $path -Name $property -Value $value
        }
    }
}

# .NET Framework Settings
$netFrameworkPaths = @(
    "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727",
    "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
)

foreach ($path in $netFrameworkPaths) {
    Set-RegistryKey -Path $path -Name "SystemDefaultTlsVersions" -Value 1
    Set-RegistryKey -Path $path -Name "SchUseStrongCrypto" -Value 1
}

# WindowsUpdate PolicyState Settings
$policyStatePath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState"
Set-RegistryKey -Path $policyStatePath -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value 0
Set-RegistryKey -Path $policyStatePath -Name "UpdateServiceUrlAlternate" -Value "" -Type "String"
Set-RegistryKey -Path $policyStatePath -Name "DisableWindowsUpdateAccess" -Value 0
Set-RegistryKey -Path $policyStatePath -Name "ElevateNonAdmins" -Value 0

# Remove any extra keys in the PolicyState path
$validKeys = @("DoNotConnectToWindowsUpdateInternetLocations", "UpdateServiceUrlAlternate", "DisableWindowsUpdateAccess", "ElevateNonAdmins")
$existingKeys = Get-ItemProperty -Path $policyStatePath | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider") } | Select-Object -ExpandProperty Name

foreach ($key in $existingKeys) {
    if ($key -notin $validKeys) {
        Remove-ItemProperty -Path $policyStatePath -Name $key
        Write-Host "Removed extra key: $policyStatePath\$key"
    }
}

Write-Host "Registry updates completed."

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
$valueName = "Functions"

if (Test-Path $regPath) {
    try {
        Remove-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop
        Write-Host "Successfully deleted the 'Transport' value from $regPath"
    }
    catch {
        Write-Host "Error deleting the 'Transport' value: $($_.Exception.Message)"
    }
}
else {
    Write-Host "Registry path does not exist: $regPath"
}

# Requires elevation
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
    Write-Warning "Please run this script as an Administrator!"
    Break
}

# Update root certificates
Write-Host "Updating root certificates..."
certutil -generateSSTFromWU roots.sst

# Reset Windows Update components
Write-Host "Resetting Windows Update components..."
Stop-Service -Name wuauserv, cryptSvc, bits, msiserver -Force

Rename-Item -Path C:\Windows\SoftwareDistribution -NewName SoftwareDistribution.old -Force
Rename-Item -Path C:\Windows\System32\catroot2 -NewName catroot2.old -Force

Start-Service -Name wuauserv, cryptSvc, bits, msiserver

# Force Windows Update to use HTTPS
Write-Host "Configuring Windows Update to use HTTPS..."
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

if (!(Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

New-ItemProperty -Path $regPath -Name "DisableWindowsUpdateAccess" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path $regPath -Name "WUServer" -Value "https://windowsupdate.microsoft.com" -PropertyType String -Force
New-ItemProperty -Path $regPath -Name "WUStatusServer" -Value "https://windowsupdate.microsoft.com" -PropertyType String -Force

# Run Windows Update troubleshooter
#Write-Host "Running Windows Update troubleshooter..."
#Get-TroubleshootingPack -Path "C:\Windows\diagnostics\system\WindowsUpdate" | Invoke-TroubleshootingPack

# Restart Windows Update service
Write-Host "Restarting Windows Update service..."
Restart-Service -Name wuauserv

Write-Host "Script completed. Please restart your computer and manually check for updates."


function Fail() {
	Param(
		[string]$Message
	)
	Write-Warning $Message
	Write-Output ""
	Write-Warning "Root Certificate Updater has failed. Please make sure you are connected to the Internet, have the latest version of PowerShell, and that you are running this script with the appropriate permissions."
	Write-Output ""
	Pop-Location
	Break
}

# Space
Clear-Host
Write-Output "";


# Wait 10 seconds before continuing, let user know
If (!$Force) {
	Write-Output ""
	Write-Output "Certificate Trust Lists will be updated in 10 seconds. Press CTRL+C to cancel."
	Write-Output ""
	Start-Sleep -Seconds 10
	Write-Output $("-" * 50)
}

# Check if Windows Update is allowed to update trusted root certificates
Write-Output "Checking if Windows Update is allowed to update 'trusted' root certificates...";
Write-Output "";
$ShowAUMessage = $true;
If ($val = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\SystemCertificates\AuthRoot' -Name 'DisableRootAutoUpdate' -ErrorAction Ignore) {
	If ($val.DisableRootAutoUpdate -eq 1) {
		Write-Warning "Your settings do NOT allow 'trusted' root certificate updates through Windows Update.";
		Write-Output "";
		Write-Output "    To change, check the 'DisableRootAutoUpdate' value in the registry key";
		Write-Output "        'HKLM\Software\Policies\Microsoft\SystemCertificates\AuthRoot'";
		$ShowAUMessage = $false;
	}
}
If ($ShowAUMessage) {
	Write-Output "    Windows is configured automatically update 'trusted' root certificates through Windows Update";
}
Write-Output "";

# Check if Windows Update is allowed to download untrusted root certificates
Write-Output "Checking if Windows Update is allowed to update 'untrusted' root certificates...";
Write-Output "";
$ShowAUMessageD = $true;
If ($val = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\SystemCertificates\AuthRoot' -Name 'EnableDisallowedCertAutoUpdate' -ErrorAction Ignore) {
	If ($val.EnableDisallowedCertAutoUpdate -eq 0) {
		Write-Warning "Your settings do NOT allow 'untrusted' root certificate updates through Windows Update.";
		Write-Output "";
		Write-Output "    To change, check the 'EnableDisallowedCertAutoUpdate' value in the registry key";
		Write-Output "        'HKLM\Software\Policies\Microsoft\SystemCertificates\AuthRoot'";
		$ShowAUMessageD = $false;
	}
}
If ($ShowAUMessageD) {
	Write-Output "    Windows is configured automatically update 'untrusted' root certificates through Windows Update";
}
Write-Output $("-" * 50);
Write-Output "";

# Remember current directory
Push-Location $pwd

# Go to temporary directory
$TempDir = [System.IO.Path]::GetTempPath()
Set-Location $TempDir

# Download the latest root certificates
$ProgressPreference = "SilentlyContinue"
Write-Output "Downloading the latest Certificate Trust Lists files from Microsofft...";
Write-Output "";
Invoke-WebRequest -Uri "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab" -OutFile "authrootstl.cab"
Invoke-WebRequest -Uri "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab" -OutFile "disallowedcertstl.cab"

# Confirm the files downloaded
if (-NOT (Test-Path authrootstl.cab)) {
	Fail -Message "authrootstl.cab not found. Check your Internet connection and try again."
}
if (-NOT (Test-Path disallowedcertstl.cab)) {
	Fail -Message "disallowedcertstl.cab not found. Check your Internet connection and try again."
}

# Extract certificates from cab files
expand authrootstl.cab -R .\
expand disallowedcertstl.cab -R .\

# Confirm the files extracted
if (-NOT (Test-Path authroot.stl)) {
	Fail -Message "authroot.stl not found after trying to extract it from authrootstl.cab. This may be a bug."
}
if (-NOT (Test-Path disallowedcert.stl)) {
	Fail -Message "disallowedcert.stl not found after trying to extract it from authrootstl.cab. This may be a bug."
}

# Add stl (certificate) files
certutil -f -addstore root authroot.stl
certutil -f -addstore disallowed disallowedcert.stl

# Wait a second
Start-Sleep -Seconds 1

# Delete temp files
Remove-Item authrootstl.cab, disallowedcertstl.cab
Remove-Item authroot.stl, disallowedcert.stl

# Message to user
Write-Output ""
Write-Output $("-" * 50)
Write-Output "The root certificates lists were successfully downloaded and installed. When your computer sees a root certificate it hasn't encountered before, it will automatically download it."
Write-Output ""
Write-Output "Please restart the computer for changes to take effect."
Write-Output $("-" * 50)
Write-Output ""
