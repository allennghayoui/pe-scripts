<#
	.SYNOPSIS
	Creates a new SQL Server instance.

	.DESCRIPTION
	Creates and sets up a new SQL Server instance on the target machine.

	.PARAMETER InstanceName
	Specifies the name of the new SQL Server instance.

	.PARAMETER SqlSvcUsername
	Specifies the username for the SQL Server Service account.

	.PARAMETER SqlSvcPassword
	Specifies the password for the SQL Server Service account.

	.PARAMETER SqlSysAdminAccounts
	Specifies the accounts to be given the SQL 'sysadmin' role on the new SQL Server instance.

	.PARAMETER SaPassword
	Specifies the password for the 'sa' user on the new SQL Server instance.

	.PARAMETER FQDN
	Specifies the Fully Qualified Domain Name of the domain that the machine is joined to (in case of a domain-joined installation).

	.PARAMETER SqlSvcStartupType
	Specifies the SQL Server service startup type.

	.EXAMPLE
	(includes domain name with usernames)
	PS> .\sql_server.ps1 -InstanceName "NEWSQL" -SqlSvcUsername "DOMAIN\sql_svc" -SqlSvcPassword "P@ssw0rd" -SqlSysAdminAccounts "DOMAIN\sql_svc","DOMAIN\johndoe" -SaPassword "P@ssw0rd" -FQDN "domain.local"

	.EXAMPLE
	(does not include domain name with usernames)
	PS> .\sql_server.ps1 -InstanceName "NEWSQL" -SqlSvcUsername "sql_svc" -SqlSvcPassword "P@ssw0rd" -SqlSysAdminAccounts "sql_svc","johndoe" -SaPassword "P@ssw0rd" -FQDN "domain.local"

	.EXAMPLE
	(setup for local accounts)
	PS> .\sql_server.ps1 -InstanceName "NEWSQL" -SqlSvcUsername "local_sql_svc" -SqlSvcPassword "P@ssw0rd" -SqlSysAdminAccounts "local_sql_svc","local_johndoe" -SaPassword "P@ssw0rd"

#>

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

######################################## Function Declarations ########################################

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
			$domain, $usernameWithoutPrefix = SplitPrefixFromUsername -Username $RemoveUser
			
			Write-Host "[*] Removing user $RemoveUser..."
			
			Remove-ADUser -Identity $usernameWithoutPrefix -Confirm:$false
			
			Write-Host "[+] Removed user $RemoveUser."
			
			return
		}
		
		$isLocalUser = CheckForLocalUserPrefix -Username $RemoveUser
		if ($isLocalUser)
		{
			$dotPrefix, $usernameWithoutPrefix = SplitPrefixFromUsername -Username $RemoveUser
		}
		
		Write-Host "[*] Removing user $RemoveUser..."
		
		Remove-LocalUser -Name $usernameWithoutPrefix -Confirm:$false
		
		Write-Host "[+] Removed user $RemoveUser."
		
		return
	}
	
	function RemoveExtraFiles
	{
		if ((Test-Path -Path $sqlServerExtractorPath))
		{
			Write-Host "[*] Removing '$sqlServerExtractorPath'..."
			Remove-Item -Path $sqlServerExtractorPath -Force
			Write-Host "[+] Removed '$sqlServerExtractorPath'."
		}

		if ((Test-Path -Path $sqlServerExprEnuSetupPath))
		{
			Write-Host "[*] Removing '$sqlServerExprEnuSetupPath'..."
			Remove-Item -Path $sqlServerExprEnuSetupPath -Force
			Write-Host "[+] Removed '$sqlServerExprEnuSetupPath'."
		}

		if ((Test-Path -Path $sqlServerSetupFilesPath))
		{
			Write-Host "[*] Removing '$sqlServerSetupFilesPath'..."
			Remove-Item -Path $sqlServerSetupFilesPath -Force -Recurse
			Write-Host "[+] Removed '$sqlServerSetupFilesPath'."
		}

		if ((Test-Path -Path $sqlServerSetupPath))
		{
			Write-Host "[*] Removing '$sqlServerSetupPath'..."
			Remove-Item -Path $sqlServerSetupPath -Force
			Write-Host "[+] Removed '$sqlServerSetupPath'."
		}
		
		if ((Test-Path -Path $sqlServerConfigFilePath))
		{
			Write-Host "[*] Removing '$sqlServerConfigFilePath'..."
			Remove-Item -Path $sqlServerConfigFilePath -Force
			Write-Host "[+] Removed '$sqlServerConfigFilePath'."
		}
	}
	
	if ((-not ($RemoveExtraFiles.IsPresent)) -and ($RemoveUser -eq ""))
	{
		Write-Host "[-] -RemoveUser and -RemoveExtraFiles cannot both be absent. Skipping file cleanup." -ForegroundColor Yellow
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

# Checks the domain validity and returns its info
function CheckDomainValidityAndGetDomainInfo
{
	param(
		[Parameter(Mandatory=$true)]
		[string] $Username,
		[Parameter(Mandatory=$true)]
		[string] $FQDN
	)
	
	$providedDomainNetBiosName, $providedUsername = SplitPrefixFromUsername -Username $Username
	
	try
	{
		$currentDomain = Get-ADDomain -ErrorAction Stop
		
		if (-not ($currentDomain.DNSRoot -ieq $FQDN))
		{
			Write-Host "[-] Current domain FQDN '$($currentDomain.DNSRoot)' and provided FQDN '$($FQDN.ToLower())' do not match." -ForegroundColor Red
			exit 1
		}
		
		if (-not ($providedDomainNetBiosName -eq $currentDomain.NetBIOSName))
		{
			Write-Host "[-] Current domain NetBIOS name '$($currentDomain.NetBIOSName)' and provided domain NetBIOSName '$($providedDomainNetBiosName)' do not match." -ForegroundColor Red
			exit 1
		}
		
		return $currentDomain
	} catch
	{
		Write-Host "[-] Failed to get current domain NetBIOS name - $_" -ForegroundColor Red
		exit 1
	}
}

function GrantSeServiceLogonRight
{
	param(
		[Parameter(Mandatory=$true)]
		[string] $User
	)

	$Right = "SeServiceLogonRight"
	$tempInfFile = New-TemporaryFile

	Write-Host "[*] Adding '$Right' for '$User'..."

	try
	{
		secedit /export /cfg "$tempInfFile.inf" | Out-Null
		(gc -Encoding ascii "$tempInfFile.inf") -replace '^SeServiceLogonRight .+', "`$0,$Username" | sc -Encoding ascii "$tempInfFile.inf"
		secedit /import /cfg "$tempInfFile.inf" /db "$tempInfFile.sdb" | Out-Null
		secedit /configure /db "$tempInfFile.sdb" /cfg "$tempInfFile.inf" | Out-Null
	} catch
	{
		Write-Host "[-] Failed to add '$Right' to '$User' - $_" -ForegroundColor Red
	}
	
	Write-Host "[+] Added '$Right' for '$User'."

	Remove-Item "$tempPath\tmp*" -Force
}

######################################## Variable Declarations ########################################

# Paths
$tempPath = "$env:TEMP"
$sqlServerConfigFilePath = "$tempPath\sqlserverconfig.ini"
$sqlServerExtractorPath = "$tempPath\sqlserverextractor.exe"
$sqlServerExprEnuSetupPath = "$tempPath\SQLEXPR_x64_ENU.exe"
$sqlServerSetupFilesPath = "$tempPath\SQLServerSetupFiles"
$sqlServerSetupPath = "$sqlServerSetupFilesPath\SETUP.EXE"

$sqlSysAdminAccountsFormattedString = ""
$sqlSvcAccount = $SqlSvcUsername

######################################## Script Starts ########################################

$isActiveDirectoryModuleAvailable = Get-Module -ListAvailable -Name ActiveDirectory
if (-not $isActiveDirectoryModuleAvailable)
{
	Write-Host "[*] Installing RSAT-AD-PowerShell..."
	Install-WindowsFeature -Name RSAT-AD-PowerShell -IncludeAllSubFeatures
	Write-Host "[+] Installed RSAT-AD-PowerShell." 
}
Import-Module ActiveDirectory


$sqlSvcContainsDomainPrefix = CheckForDomainPrefix -Username $sqlSvcAccount
$isFqdnNullOrEmpty = ($null -eq $FQDN) -or ($FQDN -eq "")

if ($isFqdnNullOrEmpty -and $sqlSvcContainsDomainPrefix)
{
	Write-Host "[-] FQDN cannot be NULL when SqlSvcUsername contains domain prefix '$SqlSvcUsername'." -ForegroundColor Red
	exit 1
}

# Case: Install for local machine and local users
if ($isFqdnNullOrEmpty -and (-not $sqlSvcContainsDomainPrefix))
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
		Write-Host "[*] '$SqlSvcUsername' does not exist. Creating user..."

		$SecurePassword = $SqlSvcPassword | ConvertTo-SecureString -AsPlainText -Force
		try
		{
			New-LocalUser `
				-Name $sqlSvcUsernameWithoutPrefix `
				-Password $SecurePassword `
				-Description "SQL Server Service Account" `
				-ErrorAction Stop
			
			Write-Host "[+] User created."
		} catch
		{
			Write-Host "[-] Failed to create user '$SqlSvcUsername' - $_"
			exit 1
		}

		Write-Host "[*] Setting '$SqlSvcUsername' to Logon as a Service Account..."
		GrantSeServiceLogonRight -User "$env:COMPUTERNAME\$sqlSvcUsernameWithoutPrefix"
		Write-Host "[+] Set '$SqlSvcUsername' to Logon as a Service Account."
	}
	
	# Check SQL sysadmin username validity
	$sqlSysAdminAccountsFormattedArray = foreach ($sqlAdmin in $SqlSysAdminAccounts)
	{
		$sqlAdminContainsDomainPrefix = CheckForDomainPrefix -Username $SqlSvcUsername
		
		if ($sqlAdminContainsDomainPrefix)
		{
			Write-Host "[-] Username '$sqlAdmin' contains a domain prefix but '$SqlSvcUsername' does not. Installation can either be local or domain-joined." -ForegroundColor Red
			
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
			Write-Host "[-] User '$sqlAdmin' does not exist - $_" -ForegroundColor Red
			
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
		Write-Host "[*] $SqlSvcUsername does not exist. Creating user..."

		$SecurePassword = $SqlSvcPassword | ConvertTo-SecureString -AsPlainText -Force
		try
		{
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
			
			Write-Host "[+] User created."

			Write-Host "[*] Setting '$SqlSvcUsername' to Logon as a Service Account..."
			GrantSeServiceLogonRight -User $SqlSvcUsername
			Write-Host "[+] Set '$SqlSvcUsername' to Logon as a Service Account."
		} catch
		{
			Write-Host "[-] Failed to create user '$SqlSvcUsername' - $_" -ForegroundColor Red
			exit 1
		}
	} catch
	{
		Write-Host "[-] Failed to find user '$SqlSvcUsername' - $_" -ForegroundColor Red
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
			Write-Host "[-] User '$sqlAdmin' does not exist - $_" -ForegroundColor Red
			
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
Write-Host "[*] Downloading SQL Server Installer into '$sqlServerExtractorPath'..."
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?linkid=2216019&culture=en-us" -OutFile $sqlServerExtractorPath -UseBasicParsing
Write-Host "[+] Downloaded SQL Server Installer into '$sqlServerExtractorPath'."

# Download SQLEXPR_x64_ENU.exe file
Write-Host "[*] Downloading 'SQLEXPR_x64_ENU.exe'..."
Start-Process -Wait -FilePath $sqlServerExtractorPath -ArgumentList "/QUIET /ACTION=Download /MEDIATYPE=Core /MEDIAPATH=$tempPath"
Write-Host "[+] Downloaded 'SQLEXPR_x64_ENU.exe'."

# Extract setup files
Write-Host "[*] Extracting setup files into '$sqlServerSetupFilesPath'..."
Start-Process -Wait -FilePath $sqlServerExprEnuSetupPath -ArgumentList "/q /x:$sqlServerSetupFilesPath"
Write-Host "[+] Extracted setup files into '$sqlServerSetupFilesPath'."

# Generate configuration '.ini' file
Write-Host "[*] Generating '$sqlServerConfigFilePath' configuration file..."

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
Write-Host "[+] Generated '$sqlServerConfigFilePath' configuration file."

# Install SQL Server Express using configuration file
Write-Host "[*] Installing SQL Server Express..."
Start-Process -Wait -FilePath $sqlServerSetupPath -ArgumentList "/IACCEPTSQLSERVERLICENSETERMS /ConfigurationFile=$sqlServerConfigFilePath"
Write-Host "[+] SQL Server installed."

# Add firewall inbound rules
Write-Host "[*] Adding Firewall Inbound Rules..."
New-NetFirewallRule -DisplayName "SQL Browser UDP" -Direction Inbound -Protocol UDP -LocalPort 1434 -Action Allow
New-NetFirewallRule -DisplayName "SQL Instance TCP" -Direction Inbound -Protocol TCP -LocalPort 1433 -Action Allow
Write-Host "[+] Added Firewall Inbound Rules."

Write-Host "[*] Cleaning Up: Removing Extra Files..."
CleanUp -RemoveExtraFiles
Write-Host "[+] Clean Up Compelete."

exit 0
