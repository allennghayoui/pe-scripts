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

if ($SqlSvcUsername -match ".*\\.*")
{
	$domain, $user = $SqlSvcUsername.Split("\")	
} else
{
	Write-Error "[!] $SqlSvcUsername does not specify the domain 'DOMAIN\username'."
	exit 1
}

# Check if SQL Service account exists
$existingUser = Get-ADUser -Filter { SamAccountName -eq $SqlSvcUsername }-Server $domain -ErrorAction Stop
	
if (-not $existingUser)
{
	Write-Host "[*] $SqlSvcUsername does not exist. Creating user..." -ForegroundColor Cyan

	$SecurePassword = $SqlSvcPassword | ConvertTo-SecureString -AsPlainText -Force
	try {
		New-ADUser -Name $SqlSvcUsername -SamAccountName $SqlSvcUsername -AccountPassword $SecurePassword -Enabled $true -PasswordNeverExpires $true -Description "SQL Server Service Account" -ErrorAction Stop
	} catch {
		Write-Error "[!] Failed to create user $SqlSvcUsername."
		Write-Error $_.Exception.Message
		exit 1
	}
}

Write-Host "[*] Installing SQL Server Express..." -ForegroundColor Cyan

$iniContent = @"
[OPTIONS]
ACTION="Install"
FEATURES=SQL
INSTANCENAME="$InstanceName"
SQLSVCACCOUNT="$SqlSvcUsername"
SQLSVCPASSWORD="$SqlSvcPassword"
SQLSVCSTARTUPTYPE="$SqlSvcStartupType"
TCPENABLED=1
"@

$sqlServerConfigFilePath = "$tempPath\sqlserverconfig.ini"

$iniContent | Out-File -FilePath $sqlServerConfigFilePath

Start-Process -FilePath $sqlServerSetupPath -ArgumentList "/CONFIGURATIONFILE=$sqlServerConfigFilePath /INSTALLPATH=`"C:\Program Files\Microsoft SQL Server`" /QUIET /IACCEPTSQLSERVERLICENSETERMS" -Wait

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
