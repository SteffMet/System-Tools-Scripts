# Script to create a scheduled task for VPN Connection Check, attempts to talk to DC if cant reach it connects.

$taskName = "VPN Connection Check"
$taskDescription = "Checks VPN connection on user logon"
$scriptPath = "C:\ProgramData\corpname\VPNCheck.ps1"

# Ensure the directory exists
$scriptDir = Split-Path -Parent $scriptPath
if (-not (Test-Path $scriptDir)) {
    New-Item -ItemType Directory -Path $scriptDir -Force
}

# Create the VPNCheck.ps1 script
$vpnCheckScript = @'
# List of domain controllers to check
$domainControllers = @(
    "dc01.mydomain",
    "dc02.mydomain",
    "dc03.mydomain",
    "dc04.mydomain"
)

# VPN portal address
$vpnPortal = "changemydomain.com"

# Function to test connectivity
function Test-DCConnectivity {
    foreach ($dc in $domainControllers) {
        if (Test-Connection -ComputerName $dc -Count 1 -Quiet) {
            return $true
        }
    }
    return $false
}

# Function to show toast notification
function Show-Notification {
    param (
        [string]$Title,
        [string]$Message
    )

    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
    [Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
    [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

    $app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
    $template = @"
<toast>
    <visual>
        <binding template="ToastText02">
            <text id="1">$Title</text>
            <text id="2">$Message</text>
        </binding>
    </visual>
</toast>
"@

    $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $xml.LoadXml($template)
    $toast = New-Object Windows.UI.Notifications.ToastNotification $xml
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show($toast)
}

# Check if we can reach any of the domain controllers
if (-not (Test-DCConnectivity)) {
    Write-Host "Unable to reach any domain controllers. Attempting to connect to VPN."
    
    # Check if Global Protect is installed
    $gpPath = "C:\Program Files\Palo Alto Networks\GlobalProtect\PanGPA.exe"
    if (Test-Path $gpPath) {
        # Attempt to connect to the VPN
        Start-Process $gpPath -ArgumentList "connect -portal $vpnPortal" -NoNewWindow -Wait
        
        # Wait for the connection to establish
        Start-Sleep -Seconds 10
        
        # Check connectivity again
        if (Test-DCConnectivity) {
            Write-Host "Successfully connected to VPN and can now reach a domain controller."
            Show-Notification -Title "VPN Connection Successful" -Message "Connected to VPN and reached a domain controller."
        } else {
            Write-Host "Connected to VPN, but still unable to reach any domain controllers."
            Show-Notification -Title "VPN Connection Warning" -Message "Connected to VPN, but unable to reach domain controllers."
        }
    } else {
        Write-Host "Global Protect client not found. Please install it or check the installation path."
        Show-Notification -Title "VPN Connection Error" -Message "Global Protect client not found. Please install it."
    }
} else {
    Write-Host "Successfully connected to a domain controller."
    Show-Notification -Title "Network Connection" -Message "Skipping VPN Connection, already on the network."
}
'@

# Save the VPNCheck.ps1 script
Set-Content -Path $scriptPath -Value $vpnCheckScript

# Create the scheduled task
$action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -GroupId "Users" -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

# Register the scheduled task
Register-ScheduledTask -TaskName $taskName -Description $taskDescription -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force

Write-Host "Scheduled task '$taskName' has been created successfully."
