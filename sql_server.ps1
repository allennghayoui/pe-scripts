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
	[string[]] $SqlSysAdminAccounts,
	[Parameter(Mandatory=$false)]
	[string] $FQDN,
	[Parameter(Mandatory=$false)]
	[ValidateSet("Automatic", "Manual", "Disabled")]
	[string] $SqlSvcStartupType = "Automatic"
)

function CleanUp
{
	param(
		[Parameter(Mandatory=$false)]
		[string] $RemoveUser,
		[Parameter(Mandatory=$false)]
		[switch] $RemoveExtraFiles = $false
	)
	
	if ((-not ($RemoveExtraFiles.IsPresent)) -and ($null -eq $RemoveUser))
	{
		Write-Error "[!] -RemoveUser and -RemoveExtraFiles cannot both be absent."
		exit 1
	}
	
	if (-not ($null -eq $RemoveUser) -and (-not ($RemoveExtraFiles.IsPresent)))
	{
		$usernameWithoutPrefix = $RemoveUser
		
		$isDomainUser = CheckForDomainPrefix -Username $RemoveUser
		if ($isDomainUser)
		{
			CheckActiveDirectoryAvailabilityAndImport
			
			$domain, $usernameWithoutPrefix = SplitPrefixFromUsername -Username $RemoveUser
			Remove-ADUser -Identity $usernameWithoutPrefix
			return
		}
		
		$isLocalUser = CheckForLocalUserPrefix -Username $RemoveUser
		if ($isLocalUser)
		{
			$dotPrefix, $usernameWithoutPrefix = SplitPrefixFromUsername -Username $RemoveUser
		}
		
		Remove-LocalUser -Name $usernameWithoutPrefix
		return
	}
	
	if ($RemoveExtraFiles.IsPresent -and ($null -eq $RemoveUser))
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
}

# Checks if user is in 'DOMAIN\user' format
# Does not match for local '.\user' format
function CheckForDomainPrefix
{
	param(
		[Parameter(Mandatory=$true)]
		[string] $Username
	)
	
	if (-not ($Username -match '^[a-zA-Z0-9_-]+\\[a-zA-Z0-9\s_-]+$'))
	{
		return $false
	}
	
	return $true
}

# Match only on local '.\user' format
function CheckForLocalUserPrefix
{
	param(
		[Parameter(Mandatory=$true)]
		[string] $Username
	)
	
	if (-not ($Username -match '^\.[\\][A-Za-z0-9\s_-]+$'))
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
		[string] $Username
	)
	
	$domain, $name = $Username.Split("\")
	return $domain, $name	
}

function CheckDomainValidityAndGetDomainInfo
{
	param(
		[Parameter(Mandatory=$true)]
		[string] $Username,
		[Parameter(Mandtory=$true)]
		[string] $FQDN
	)
	
	CheckActiveDirectoryAvailabilityAndLoad
	
	$providedDomainNetBiosName, $providedUsername = SplitPrefixFromUsername -Username $Username
	
	try
	{
		$currentDomain = Get-ADDomain -ErrorAction Stop
		
		if (-not ($currentDomain.DNSRoot -ieq $FQDN))
		{
			Write-Error "[!] Current domain FQDN '$currentDomain.DNSRoot' and provided FQDN '$FQDN.ToLower()' do not match."
			exit 1
		}
		
		if (-not ($providedDomainNetBiosName -eq $currentDomain.NetBIOSName))
		{
			Write-Error "[!] Current domain NetBIOS name '$currentDomain.NetBIOSName' and provided domain NetBIOSName '$providedDomainNetBiosName' do not match."
			exit 1
		}
		
		return $currentDomain
	} catch
	{
		Write-Error "[!] Failed to get current domain NetBIOS name."
		exit 1
	}
}

# Checks for the availability of the ActiveDirectory Module.
# Imports it if not already imported.
function CheckActiveDirectoryAvailabilityAndImport
{
	$isActiveDirectoryModuleAvailable = Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue
	if (-not $isActiveDirectoryModuleAvailable)
	{
		Write-Error "ActiveDirectory PowerShell module not found."
		exit 1
	}
	
	$isActiveDirectoryModuleImported = (Get-Module -Name ActiveDirectory).Name
	if (-not $isActiveDirectoryModuleImported)
	{
		Import-Module ActiveDirectory
	}
}


# Variables
$tempPath = "$env:TEMP"
$sqlServerSetupPath = "$tempPath\sqlserver.exe"
$sqlInstallPath = "C:\Program Files\Microsoft SQL Server"
$sqlServerConfigFilePath = "$tempPath\sqlserverconfig.ini"
$sqlSysAdminAccountsFormattedString = ""
$sqlSvcAccount = $SqlSvcUsername

# Import ActiveDirectory PowerShell module
CheckActiveDirectoryAvailabilityAndImport

$sqlSvcContainsDomainPrefix = CheckForDomainPrefix -Username $SqlSvcUsername

if ($null -eq $FQDN -and $sqlSvcContainsDomainPrefix)
{
	Write-Error "[!] FQDN cannot be NULL when SqlSvcUsername contains domain prefix '$SqlSvcUsername'."
	exit 1
}

# Case: Install for local machine and local users
if ($null -eq $FQDN -and (-not sqlSvcContainsDomainPrefix))
{
	$sqlSvcUsernameWithoutPrefix = $SqlSvcUsername
	
	# Check the SQL service username validity
	if ((CheckForLocalUserPrefix -Username $SqlSvcUsername))
	{
		$dotPrefix, $sqlSvcUsernameWithoutPrefix = SplitPrefixFromUsername -Username $SqlSvcUsername
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
	
	# Check SQL sysadmin username validity
	# Create array with 
	$sqlSysAdminAccountsFormattedArray = foreach ($sqlAdmin in $SqlSysAdminAccounts)
	{
		$sqlAdminContainsDomainPrefix = CheckForDomainPrefix -Username $SqlSvcUsername
		
		if ($sqlAdminContainsDomainPrefix)
		{
			Write-Error "[!] Username $sqlAdmin contains a domain prefix but $SqlSvcUsername does not. Installation can either be local or domain-joined."
			
			# Remove new local user created
			CleanUp -RemoveUser $sqlSvcUsernameWithoutPrefix
			
			exit 1
		}
		
		$sqlAdminWithoutPrefix = $sqlAdmin
		
		# Check the SQL service username validity
		if ((CheckForLocalUserPrefix -Username $sqlAdmin))
		{
			$dotPrefix, $sqlAdminWithoutPrefix = SplitPrefixFromUsername -Username $sqlAdmin
		}
		
		$existingUser = Get-LocalUser -Name $sqlAdminWithoutPrefix
	
		if ($existingUser)
		{
			$sqlAdminWithoutPrefix
		} else
		{
			Write-Error "[!] User $sqlAdmin does not exist."
			
			# Remove new local user created
			CleanUp -RemoveUser $sqlSvcUsernameWithoutPrefix
			
			exit 1
		}
		
	}

	# Create a space separated string of usernames to be included in the '.ini' config file
	$sqlSysAdminAccountsFormattedString = $sqlSysAdminAccountsFormattedArray -join '" "'
	
	# Set sqlSvcAccount final value
	$sqlSvcAccount = $sqlSvcUsernameWithoutPrefix
} else
{
	$domainInfo = CheckDomainValidityAndGetDomainInfo -Username $SqlSvcUsername -FQDN $FQDN
	
	$sqlSvcUsernameWithDomainPrefix = $SqlSvcUsername
	
	# Check the SQL service username validity
	if (-not (CheckForDomainPrefix -Username $SqlSvcUsername))
	{
		$domainPrefix = $domainInfo.NetBIOSName
		$sqlSvcUsernameWithDomainPrefix = "$domainPrefix\$SqlSvcUsername"
	}
	
	$domainPrefix, $sqlSvcUsernameWithoutDomainPrefix = SplitPrefixFromUsername -Username $sqlSvcUsernameWithDomainPrefix
	
	$sqlSvcUpn = "$sqlSvcUsernameWithoutDomainPrefix@$domainInfo.DNSRoot"
	
	$existingUser = Get-ADUser -Filter { UserPrincipalName -eq $sqlSvcUpn }
	
	if (-not $existingUser)
	{
		Write-Host "[*] $SqlSvcUsername does not exist. Creating user..." -ForegroundColor Cyan

		$SecurePassword = $SqlSvcPassword | ConvertTo-SecureString -AsPlainText -Force
		try {
			New-ADUser `
				-Name $sqlSvcUsernameWithoutDomainPrefix `
				-SamAccountName $sqlSvcUsernameWithoutDomainPrefix `
				-UserPrincipalName $sqlSvcUpn `
				-AccountPassword $SecurePassword `
				-Enabled $true `
				-PasswordNeverExpires $true `
				-Server $domainInfo.DNSRoot `
				-Description "SQL Server Service Account" `
				-ErrorAction Stop
			
			Write-Host "[*] User created." -ForegroundColor Cyan
		} catch {
			Write-Error "[!] Failed to create user $SqlSvcUsername."
			Write-Error $_.Exception.Message
			exit 1
		}
	}
	
	$sqlSysAdminAccountsFormattedArray = foreach ($sqlAdmin in $SqlSysAdminAccounts)
	{
		$domainInfo = CheckDomainValidityAndGetDomainInfo -Username $sqlAdmin -FQDN $FQDN
		
		$sqlAdminWithDomainPrefix = $sqlAdmin
		
		if (-not (CheckForDomainPrefix -Username $sqlAdmin))
		{
			$domainPrefix = $domainInfo.NetBIOSName
			$sqlAdminWithDomainPrefix = "$domainPrefix\$sqlAdmin"
		}
		
		$domainPrefix, $sqlAdminWithoutDomainPrefix = SplitPrefixFromUsername -Username $sqlAdminWithDomainPrefix
	
		$sqlAdminUpn = "$sqlAdminWithoutDomainPrefix@$domainInfo.DNSRoot"
		
		$existingUser = Get-ADUser -Filter { UserPrincipalName -eq $sqlAdminUpn }

		if ($existingUser)
		{
			$sqlAdminUpn
		} else
		{
			Write-Error "[!] User $sqlAdmin does not exist."
			
			# Remove new domain user created
			CleanUp -RemoveUser $sqlSvcUsernameWithoutDomainPrefix
			
			exit 1
		}
	}
	
	# Create a space separated string of usernames to be included in the '.ini' config file
	$sqlSysAdminAccountsFormattedString = $sqlSysAdminAccountsFormattedArray -join '" "'
	
	# Set sqlSvcAccount final value
	$sqlSvcAccount = $sqlSvcUsernameWithDomainPrefix
}

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
NPENABLED=1
"@
$iniContent | Out-File -FilePath $sqlServerConfigFilePath

Write-Host "[*] Installing SQL Server Express..." -ForegroundColor Cyan

try
{
	$process = Start-Process -FilePath $sqlServerSetupPath -ArgumentList "/CONFIGURATIONFILE=$sqlServerConfigFilePath /INSTALLPATH=`"$sqlInstallPath`" /QUIET /IACCEPTSQLSERVERLICENSETERMS" -PassThru -Wait
	
	if ($process.ExitCode -eq 0)
	{
		Write-Host "[*] SQL Server installed." -ForegroundColor Cyan
	} else
	{
		Write-Error "[!] Failed to install SQL Server with exit code $($process.ExitCode)."
		
		CleanUp -RemoveUser $sqlSvcAccount
		
		exit 1
	}
} catch
{
	Write-Error "[!] An error occurred while starting the SQL Server setup process."
	Write-Error $_.Exception.Message
	
	CleanUp -RemoveUser $sqlSvcAccount
	
	exit 1
}

CleanUp -RemoveExtraFiles

exit 0
