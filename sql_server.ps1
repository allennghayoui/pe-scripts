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
	[string] $FQDN,
	[Parameter(Mandatory=$true)]
	[string] $SqlSvcUsername,
	[Parameter(Mandatory=$true)]
	[string] $SqlSvcPassword,
	[Parameter(Mandatory=$true)]
	[string[]] $SqlSysAdminAccounts,
	[Parameter(Mandatory=$true)]
	[switch] $DomainJoined,
	[Parameter(Mandatory=$false)]
	[ValidateSet("Automatic", "Manual", "Disabled")]
	[string] $SqlSvcStartupType = "Automatic"
)

# Cleans up useless files after the setup
function CleanUp
{
	Write-Host "[*] Removing $sqlServerSetupPath..." -ForegroundColor Cyan
	Remove-Item -Path $sqlServerSetupPath -Force

	$sqlServerSetupExists = Test-Path -Path $sqlServerSetupPath
	if ($sqlServerSetupExists)
	{
		Write-Error "[!] Failed to remove $sqlServerSetupPath."
		exit 1
	}
	
	Write-Host "[*] Removed $sqlServerSetupPath." -ForegroundColor Cyan
	
	Write-Host "[*] Removing $sqlServerConfigFilePath..." -ForegroundColor Cyan
	Remove-Item -Path $sqlServerConfigFilePath -Force

	$sqlServerConfigFileExists = Test-Path -Path $sqlServerConfigFilePath
	if ($sqlServerConfigFileExists)
	{
		Write-Error "[!] Failed to remove $sqlServerConfigFilePath."
		exit 1
	}
	
	Write-Host "[*] Removed $sqlServerConfigFilePath." -ForegroundColor Cyan
}

# Checks if user is in 'DOMAIN\user' format
function CheckForUsernamePrefix
{
	param(
		[Parameter(Mandatory=$true)]
		[string] $NameToCheck
	)
	
	if (-not ($NameToCheck -match '^[a-zA-Z0-9_-]+\\[a-zA-Z0-9\s_-]+$'))
	{
		return $false
	}
	
	return $true
}

# Splits domain from username
function SplitPrefixFromUsername
{
	param(
		[Parameter(Mandatory=$true)]
		[string] $NameToSplit
	)
	
	$domain, $name = $NameToSplit.Split("\")
	return $domain, $name	
}

# Variables
$tempPath = "$env:TEMP"
$sqlServerSetupPath = "$tempPath\sqlserver.exe"
$sqlInstallPath = "C:\Program Files\Microsoft SQL Server"
$sqlServerConfigFilePath = "$tempPath\sqlserverconfig.ini"
$sqlSvcAccount = $SqlSvcUsername

$isActiveDirectoryModuleAvailable = Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue
if (-not $isActiveDirectoryModuleAvailable)
{
	Write-Error "ActiveDirectory PowerShell module not found."
	exit 1
}

Import-Module ActiveDirectory
$isActiveDirectoryModuleLoaded = (Get-Module -Name ActiveDirectory).Name
if (-not $isActiveDirectoryModuleLoaded)
{
	Write-Error "[!] Failed to load ActiveDirectory PowerShell module."
	exit 1
}

if ($DomainJoined.IsPresent)
{
	$sqlSvcUsernameWithoutPrefix = $SqlSvcUsername
	# Check the SQL service username validity
	if ((CheckForUsernamePrefix -NameToCheck $SqlSvcUsername))
	{
		$sqlSvcDomain, $sqlSvcUsernameWithoutPrefix = SplitPrefixFromUsername -NameToSplit $SqlSvcUsername
	}

	# Check if SQL Service account exists
	$sqlSvcUpn = "$sqlSvcUsernameWithoutPrefix@$FQDN"
	$sqlSvcAccount = $sqlSvcUpn
	
	$existingUser = Get-ADUser -Filter { UserPrincipalName -eq $sqlSvcUpn }
	
	if (-not $existingUser)
	{
		Write-Host "[*] $SqlSvcUsername does not exist. Creating user..." -ForegroundColor Cyan

		$SecurePassword = $SqlSvcPassword | ConvertTo-SecureString -AsPlainText -Force
		try {
			New-ADUser `
				-Name $sqlSvcUsernameWithoutPrefix `
				-SamAccountName $sqlSvcUsernameWithoutPrefix `
				-UserPrincipalName $sqlSvcUpn `
				-AccountPassword $SecurePassword `
				-Enabled $true `
				-PasswordNeverExpires $true `
				-Server $FQDN `
				-Description "SQL Server Service Account" `
				-ErrorAction Stop
			
			Write-Host "[*] User created." -ForegroundColor Cyan
		} catch {
			Write-Error "[!] Failed to create user $SqlSvcUsername."
			Write-Error $_.Exception.Message
			exit 1
		}
	}
} else
{
	$sqlSvcUsernameWithoutPrefix = $SqlSvcUsername
	# Check the SQL service username validity
	if ((CheckForUsernamePrefix -NameToCheck $SqlSvcUsername))
	{
		$sqlSvcDomain, $sqlSvcUsernameWithoutPrefix = SplitPrefixFromUsername -NameToSplit $SqlSvcUsername
	}
	
	$existingUser = Get-LocalUser -Name $sqlSvcUsernameWithoutPrefix
	
	if (-not $existingUser)
	{
		Write-Host "[*] $SqlSvcUsername does not exist. Creating user..." -ForegroundColor Cyan

		$SecurePassword = $SqlSvcPassword | ConvertTo-SecureString -AsPlainText -Force
		try {
			New-LocalUser `
				-Name $sqlSvcUsernameWithoutPrefix `
				-SamAccountName $sqlSvcUsernameWithoutPrefix `
				-AccountPassword $SecurePassword `
				-Disabled $false `
				-AccountNeverExpires $true `
				-PasswordNeverExpires $true `
				-Description "SQL Server Service Account" `
				-ErrorAction Stop
			
			Write-Host "[*] User created." -ForegroundColor Cyan
		} catch {
			Write-Error "[!] Failed to create user $SqlSvcUsername."
			Write-Error $_.Exception.Message
			exit 1
		}
	}
}

# Check SQL sysadmin username validity
$sqlSysAdminAccountsFormattedArray = foreach ($sqlAdmin in $SqlSysAdminAccounts)
{
	if ((CheckForUsernamePrefix -NameToCheck $sqlAdmin))
	{
		$sqlAdminDomain, $sqlAdminUsernameWithoutDomain = SplitPrefixFromUsername -NameToSplit $sqlAdmin
		
		$sqlAdminUpn = "$sqlAdminUsernameWithoutDomain@$FQDN"
		

		$existingUser = Get-ADUser -Filter { UserPrincipalName -eq $sqlAdminUpn }

		if ($existingUser)
		{
			$sqlAdminUpn
		} else
		{
			Write-Error "[!] User $sqlAdmin does not exist."
			exit 1
		}
	} else
	{
		$existingUser = Get-LocalUser -Name $sqlAdmin
	
		if ($existingUser)
		{
			$sqlAdmin
		} else
		{
			Write-Error "[!] User $sqlAdmin does not exist."
			exit 1
		}
	}
	
}

# Create a space separated string of usernames to be included in the .ini config file
$sqlSysAdminAccountsFormattedString = $sqlSysAdminAccountsFormattedArray -join '" "'

# Download SQL Server Installer
Write-Host "[*] Downloading SQL Server Installer into $sqlServerSetupPath..." -ForegroundColor Cyan
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?linkid=2216019&culture=en-us" -OutFile $sqlServerSetupPath -UseBasicParsing

Write-Host "[*] Generating '.ini' configuration file..." -ForegroundColor Cyan
$iniContent = @"
[OPTIONS]
ACTION="Install"
FEATURES=SQL
INSTANCENAME="$InstanceName"
SQLSVCACCOUNT="$sqlSvcAccount"
SQLSVCPASSWORD="$SqlSvcPassword"
SQLSVCSTARTUPTYPE="$SqlSvcStartupType"
SQLSYSADMINACCOUNTS="$sqlSysAdminAccountsFormattedString"
ADDCURRENTUSERASSQLADMIN=FALSE
TCPENABLED=1
"@
$iniContent | Out-File -FilePath $sqlServerConfigFilePath

Write-Host "[*] Installing SQL Server Express..." -ForegroundColor Cyan
Start-Process -FilePath $sqlServerSetupPath -ArgumentList "/CONFIGURATIONFILE=$sqlServerConfigFilePath /INSTALLPATH=`"$sqlInstallPath`" /QUIET /IACCEPTSQLSERVERLICENSETERMS" -Wait

CleanUp

exit 0
