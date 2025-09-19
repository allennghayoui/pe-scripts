# 1. SQL Server is paid only Express edition is free
# https://www.microsoft.com/en/sql-server/sql-server-downloads
# Difference between editions is in the limit max 10GB DBs 1GB of memory
# and 1 processors. No agent for task automation, backup compression,
# log shipping, and advanced business intelligence tools.
#
# SQL Server Express 2022 download link
# https://go.microsoft.com/fwlink/p/?linkid=2216019&culture=en-us

############################################################################

param(
	[Parameter(Mandatory=$true)]
	[string] $InstanceName,
	[Parameter(Mandatory=$true)]
	[string] $SqlSvcUsername,
	[Parameter(Mandatory=$true)]
	[string] $SqlSvcPassword,
	[Parameter(Mandatory=$true)]
	[string] $SqlSysAdminsGroup,
	[Parameter(Mandatory=$false)]
	[ValidateSet("Automatic", "Manual", "Disabled")]
	[string] $SqlSvcStartupType = "Automatic"
)

# Paths
$tempPath = "$env:TEMP"
$sqlServerSetupPath = "$tempPath\sqlserver.exe"

# Download SQL Server Installer
Write-Host "[*] Downloading SQL Server Installer into $sqlServerSetupPath..." -ForegroundColor Cyan
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?linkid=2216019&culture=en-us" -OutFile $sqlServerSetupPath -UseBasicParsing

Write-Host "[*] Installing SQL Server Express..." -ForegroundColor Cyan

& "$sqlServerSetupPath" /Quiet /IAcceptSqlServerLicenseTerms /Action=Install `
	/InstallPath="C:\Program Files\Microsoft SQL Server" `
	/INSTANCENAME=$InstanceName `
	/SQLSVCACCOUNT="$SqlSvcUsername" /SQLSVCPASSWORD="$SqlSvcPassword" /SQLSVCSTARTUPTYPE="$SqlSvcStartupType" `
	/SQLSYSADMINACCOUNTS="$SqlSysAdminsGroup" `
	/TCPENABLED=1

Write-Host "[*] Removing $sqlServerSetupPath..." -ForegroundColor Cyan

Remove-Item -Path $sqlServerSetupPath -Force

$sqlServerSetupExists = Test-Path -Path $sqlServerSetupPath
if ($sqlServerSetupExists)
{
	Write-Error "[!] Failed to remove $sqlServerSetupPath."
	exit 1
}

Write-Host "[*] Removed $sqlServerSetupPath." -ForegroundColor Cyan

exit 0
