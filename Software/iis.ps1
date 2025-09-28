<#
	.SYNOPSIS
	Sets up IIS on a Windows Server machine.

	.DESCRIPTION
	Sets up IIS on a Windows Server machine.

	.EXAMPLE
	PS> .\iis.ps1
#>

# Check if ServerManager module exists
$isServerManagerModuleInstalled = Get-Module -ListAvailable -Name ServerManager

if (-not $isServerManagerModuleInstalled)
{
	Write-Error "[-] ServerManager module not found."
	exit 1
}

Import-Module ServerManager

Write-Host "[*] Installing IIS..." -ForegroundColor Cyan
Install-WindowsFeature -Name Web-Server -IncludeAllSubFeature -IncludeManagementTools

$IISFeature = Get-WindowsFeature -Name Web-Server
$IISInstalled = $IISFeature.Installed

if (-not $IISInstalled)
{
	Write-Error "[-] IIS installation failed."
	exit 1
}

Write-Host "[*] IIS installed." -ForegroundColor Cyan

# Reset IIS to apply changes
iisreset

exit 0
