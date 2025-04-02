# Check if GlobalProtect is installed
$gpPath = "C:\Program Files\Palo Alto Networks\GlobalProtect"
$gpExe = "C:\Program Files\Palo Alto Networks\GlobalProtect\PanGPA.exe"

if (Test-Path $gpPath) {
    if (Test-Path $gpExe) {
        $gpVersion = (Get-Item $gpExe).VersionInfo.FileVersion
        Write-Output "GlobalProtect is installed. Version: $gpVersion"
        exit 0
    } else {
        Write-Output "GlobalProtect folder exists, but PanGPA.exe is missing."
        exit 1
    }
} else {
    Write-Output "GlobalProtect is not installed."
    exit 1
}