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
	[Parameter(Mandatory=$true)]
	[string] $SaPassword,
	[Parameter(Mandatory=$false)]
	[string] $FQDN,
	[Parameter(Mandatory=$false)]
	[ValidateSet("Automatic", "Manual", "Disabled")]
	[string] $SqlSvcStartupType = "Automatic"
)


#########################################################
#########################################################
################  FUNCTION DECLARATIONS  ################
#########################################################
#########################################################

function CleanUp
{
	param(
		[Parameter(Mandatory=$false)]
		[string] $RemoveUser,
		[Parameter(Mandatory=$false)]
		[switch] $RemoveExtraFiles = $false
	)
	
	function RemoveUser
	{
		$usernameWithoutPrefix = $RemoveUser
		
		$isDomainUser = CheckForDomainPrefix -Username $RemoveUser
		if ($isDomainUser)
		{
			CheckActiveDirectoryAvailabilityAndImport
			
			$domain, $usernameWithoutPrefix = SplitPrefixFromUsername -Username $RemoveUser
			
			Write-Host "[*] Removing user $RemoveUser..." -ForegroundColor Cyan
			
			Remove-ADUser -Identity $usernameWithoutPrefix -Confirm:$false
			
			Write-Host "[*] Removed user $RemoveUser." -ForegroundColor Cyan
			
			return
		}
		
		$isLocalUser = CheckForLocalUserPrefix -Username $RemoveUser
		if ($isLocalUser)
		{
			$dotPrefix, $usernameWithoutPrefix = SplitPrefixFromUsername -Username $RemoveUser
		}
		
		Write-Host "[*] Removing user $RemoveUser..." -ForegroundColor Cyan
		
		Remove-LocalUser -Name $usernameWithoutPrefix -Confirm:$false
		
		Write-Host "[*] Removed user $RemoveUser." -ForegroundColor Cyan
		
		return
	}
	
	function RemoveExtraFiles
	{
		if ((Test-Path -Path $sqlServerSetupPath))
		{
			Write-Host "[*] Removing '$sqlServerSetupPath'..." -ForegroundColor Cyan
			Remove-Item -Path $sqlServerSetupPath -Force
			Write-Host "[*] Removed '$sqlServerSetupPath'." -ForegroundColor Cyan
		}
		
		if ((Test-Path -Path $sqlServerConfigFilePath))
		{
			Write-Host "[*] Removing '$sqlServerConfigFilePath'..." -ForegroundColor Cyan
			Remove-Item -Path $sqlServerConfigFilePath -Force
			Write-Host "[*] Removed '$sqlServerConfigFilePath'." -ForegroundColor Cyan
		}
		
		if ((Test-Path -Path $sqlServerSetupStdoutPath))
		{
			Write-Host "[*] Removing '$sqlServerSetupStdoutPath'..." -ForegroundColor Cyan
			Remove-Item -Path $sqlServerSetupStdoutPath -Force
			Write-Host "[*] Removed '$sqlServerSetupStdoutPath'." -ForegroundColor Cyan
		}
		
		if ((Test-Path -Path $sqlServerSetupStderrPath))
		{
			Write-Host "[*] Removing '$sqlServerSetupStderrPath'..." -ForegroundColor Cyan
			Remove-Item -Path $sqlServerSetupStderrPath -Force
			Write-Host "[*] Removed '$sqlServerSetupStderrPath'." -ForegroundColor Cyan
		}
	}
	
	if ((-not ($RemoveExtraFiles.IsPresent)) -and ($RemoveUser -eq ""))
	{
		Write-Error "[!] -RemoveUser and -RemoveExtraFiles cannot both be absent."
		exit 1
	}
	
	if (($RemoveUser -ne "") -and (-not ($RemoveExtraFiles.IsPresent)))
	{
		RemoveUser
		return
	}
	
	if ($RemoveExtraFiles.IsPresent -and ($RemoveUser -eq ""))
	{
		RemoveExtraFiles
		return
	}
	
	if ($RemoveExtraFiles.IsPresent -and ($RemoveUser -eq ""))
	{
		RemoveUser
		RemoveExtraFiles
		return
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
		[Parameter(Mandatory=$true)]
		[string] $FQDN
	)
	
	CheckActiveDirectoryAvailabilityAndImport
	
	$providedDomainNetBiosName, $providedUsername = SplitPrefixFromUsername -Username $Username
	
	try
	{
		$currentDomain = Get-ADDomain -ErrorAction Stop
		
		if (-not ($currentDomain.DNSRoot -ieq $FQDN))
		{
			Write-Error "[!] Current domain FQDN '$($currentDomain.DNSRoot)' and provided FQDN '$($FQDN.ToLower())' do not match."
			exit 1
		}
		
		if (-not ($providedDomainNetBiosName -eq $currentDomain.NetBIOSName))
		{
			Write-Error "[!] Current domain NetBIOS name '$($currentDomain.NetBIOSName)' and provided domain NetBIOSName '$($providedDomainNetBiosName)' do not match."
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

#################################################
#################################################
################  SCRIPT STARTS  ################
#################################################
#################################################

# Variables
$tempPath = "$env:TEMP"
$sqlServerConfigFilePath = "$tempPath\sqlserverconfig.ini"
$sqlServerExtractorPath = "$tempPath\sqlserverextractor.exe"
$sqlServerExprEnuSetupPath = "$tempPath\SQLEXPR_x64_ENU.exe"
$sqlServerSetupFilesPath = "$tempPath\SQLServerSetupFiles"
$sqlServerSetupPath = "$sqlServerSetupFilesPath\SETUP.EXE"
$sqlSysAdminAccountsFormattedString = ""
$sqlSvcAccount = $SqlSvcUsername

# Import ActiveDirectory PowerShell module
CheckActiveDirectoryAvailabilityAndImport

$sqlSvcContainsDomainPrefix = CheckForDomainPrefix -Username $SqlSvcUsername
$isFqdnNullOrEmpty = ($null -eq $FQDN) -or ($FQDN -eq "")

if ($isFqdnNullOrEmpty -and $sqlSvcContainsDomainPrefix)
{
	Write-Error "[!] FQDN cannot be NULL when SqlSvcUsername contains domain prefix '$SqlSvcUsername'."
	exit 1
}

# Case: Install for local machine and local users
if ($null -eq $FQDN -and (-not $sqlSvcContainsDomainPrefix))
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
			Write-Error "[!] Failed to create user '$SqlSvcUsername'."
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
			Write-Error "[!] Username '$sqlAdmin' contains a domain prefix but '$SqlSvcUsername' does not. Installation can either be local or domain-joined."
			
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
			"`"$sqlAdminWithoutPrefix`""
		} else
		{
			Write-Error "[!] User '$sqlAdmin' does not exist."
			
			# Remove new local user created
			CleanUp -RemoveUser $sqlSvcUsernameWithoutPrefix
			
			exit 1
		}
		
	}

	# Create a space separated string of usernames to be included in the '.ini' config file
	$sqlSysAdminAccountsFormattedString = $sqlSysAdminAccountsFormattedArray -join ' '
	
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
	
	try
	{
		Get-ADUser -Identity $sqlSvcUsernameWithoutDomainPrefix
	} catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
	{
		Write-Host "[*] $SqlSvcUsername does not exist. Creating user..." -ForegroundColor Cyan

		$SecurePassword = $SqlSvcPassword | ConvertTo-SecureString -AsPlainText -Force
		try {
			New-ADUser `
				-Name $sqlSvcUsernameWithoutDomainPrefix `
				-SamAccountName $sqlSvcUsernameWithoutDomainPrefix `
				-UserPrincipalName "$($sqlSvcUsernameWithoutDomainPrefix)@$($FQDN.ToLower())" `
				-AccountPassword $SecurePassword `
				-Enabled $true `
				-PasswordNeverExpires $true `
				-Server $domainInfo.DNSRoot `
				-Description "SQL Server Service Account" `
				-ErrorAction Stop
			
			Write-Host "[*] User created." -ForegroundColor Cyan
		} catch
		{
			Write-Error "[!] Failed to create user '$SqlSvcUsername'."
			Write-Error $_.Exception.Message
			exit 1
		}
	} catch
	{
		Write-Error $_.Exception.Message
		exit 1
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
		try
		{
			Get-ADUser -Identity $sqlAdminWithoutDomainPrefix | Out-Null
			"`"$sqlAdminWithDomainPrefix`""
		} catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
		{
			Write-Error "[!] User '$sqlAdmin' does not exist."
			
			# Remove new domain user created
			CleanUp -RemoveUser $sqlSvcUsernameWithoutDomainPrefix
			
			exit 1
		}
	}
	
	# Create a space separated string of usernames to be included in the '.ini' config file
	$sqlSysAdminAccountsFormattedString = $sqlSysAdminAccountsFormattedArray -join ' '
	
	# Set sqlSvcAccount final value
	$sqlSvcAccount = $sqlSvcUsernameWithDomainPrefix
}

# Download SQL Server Installer
Write-Host "[*] Downloading SQL Server Installer into $sqlServerSetupPath..." -ForegroundColor Cyan
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?linkid=2216019&culture=en-us" -OutFile $sqlServerSetupPath -UseBasicParsing

# Download SQLEXPR_x64_ENU.exe file
Write-Host "[*] Downloading SQLEXPR_x64_ENU.exe..." -ForegroundColor Cyan
Start-Process -Wait -FilePath $sqlServerExtractorPath -ArgumentList "/QUIET /ACTION=Download /MEDIATYPE=Core /MEDIAPATH=$tempPath"
Write-Host "[*] Downloaded SQLEXPR_x64_ENU.exe." -ForegroundColor Cyan

# Extract setup files
Write-Host "[*] Extracting setup files into $sqlServerSetupFilesPath..." -ForegroundColor Cyan
Start-Process -Wait -FilePath $sqlServerExprEnuSetupPath -ArgumentList "/q /x:$sqlServerSetupFilesPath"
Write-Host "[*] Extracted setup files into $sqlServerSetupFilesPath." -ForegroundColor Cyan

# Generate configuration '.ini' file
Write-Host "[*] Generating $sqlServerConfigFilePath configuration file..." -ForegroundColor Cyan

$iniContent = @"
[OPTIONS]
ACTION="Install"
QUIET="True"
; UIMODE="Normal"
UpdateEnabled="True"
USEMICROSOFTUPDATE="False"
SUPPRESSPAIDEDITIONNOTICE="False"
UpdateSource="MU"
SECURITYMODE="SQL"
BROWSERSTARTUPTYPE="Disabled"
INDICATEPROGRESS="True"
FEATURES="SQLEngine"
INSTANCENAME="$InstanceName"
INSTANCEID="$InstanceName"
SQLSVCACCOUNT="$sqlSvcAccount"
SQLSVCPASSWORD="$SqlSvcPassword"
SQLSVCSTARTUPTYPE="$SqlSvcStartupType"
SQLSYSADMINACCOUNTS=$sqlSysAdminAccountsFormattedString
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
SAPWD="$SaPassword"
"@

$iniContent | Out-File -FilePath $sqlServerConfigFilePath

Write-Host "[*] Configuration file generated." -ForegroundColor Cyan

# Install SQL Server Express using configuration file
Write-Host "[*] Installing SQL Server Express..." -ForegroundColor Cyan

Start-Process -Wait -FilePath $sqlServerSetupPath -ArgumentList "/IACCEPTSQLSERVERLICENSETERMS /ConfigurationFile=$sqlServerConfigFilePath"

Write-Host "[*] SQL Server installed." -ForegroundColor Cyan

CleanUp -RemoveExtraFiles

exit 0
