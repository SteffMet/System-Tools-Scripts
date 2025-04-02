# Start transcript logging
Start-Transcript -Path "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\RDPFilesLog.txt" -Append

try {
    # Create RDP files
    $rdpTargets = @(
        @{Name = "RDP 1"; Target = "RDP1.mydomain"},
        @{Name = "RDP 2"; Target = "RDP2.mydomain"},
        @{Name = "RDP 3"; Target = "RDP3.mydomain"}
    )

    # Ensure we're using the Public Desktop path
    $desktopPath = [Environment]::GetFolderPath("CommonDesktopDirectory")

    foreach ($rdp in $rdpTargets) {
        $rdpFilePath = Join-Path -Path $desktopPath -ChildPath "$($rdp.Name).rdp"
        
        $rdpContent = @"
screen mode id:i:2
use multimon:i:0
desktopwidth:i:1920
desktopheight:i:1080
session bpp:i:32
winposstr:s:0,3,0,0,800,600
compression:i:1
keyboardhook:i:2
audiocapturemode:i:0
videoplaybackmode:i:1
connection type:i:7
networkautodetect:i:1
bandwidthautodetect:i:1
displayconnectionbar:i:1
enableworkspacereconnect:i:0
disable wallpaper:i:0
allow font smoothing:i:1
allow desktop composition:i:1
disable full window drag:i:0
disable menu anims:i:0
disable themes:i:0
disable cursor setting:i:0
bitmapcachepersistenable:i:1
full address:s:$($rdp.Target)
audiomode:i:0
redirectprinters:i:1
redirectcomports:i:0
redirectsmartcards:i:1
redirectclipboard:i:1
redirectposdevices:i:0
autoreconnection enabled:i:1
authentication level:i:2
prompt for credentials:i:0
negotiate security layer:i:1
remoteapplicationmode:i:0
alternate shell:s:
shell working directory:s:
gatewayhostname:s:
gatewayusagemethod:i:4
gatewaycredentialssource:i:4
gatewayprofileusagemethod:i:0
promptcredentialonce:i:0
gatewaybrokeringtype:i:0
use redirection server name:i:0
rdgiskdcproxy:i:0
kdcproxyname:s:
"@

        # Use Set-Content instead of Out-File for better control
        Set-Content -Path $rdpFilePath -Value $rdpContent -Force
        Write-Output "Created RDP file: $rdpFilePath"
    }

    Write-Output "Script executed successfully"
    Exit 0
}
catch {
    $errorMessage = $_.Exception.Message
    Write-Error "An error occurred: $errorMessage"
    # Log the error to a file
    $errorMessage | Out-File "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\RDPFilesError.log" -Append
    Exit 1
}
finally {
    # Stop transcript logging
    Stop-Transcript
}
