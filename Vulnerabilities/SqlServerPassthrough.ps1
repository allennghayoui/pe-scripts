<#
	.SYNOPSIS
	Sets up SQL Server current local login passthrough vulnerability.

	.DESCRIPTION
	Sets up SQL Server current local login passthrough vulnerability.

	.PARAMETER LinkName
	Specifies the name of the SQL Server link.

	.PARAMETER LocalServerInstance
	Specifies the name of the SQL Server instance on the local machine.

	.PARAMETER RemoteServerInstance
	Specifies the name of the SQL Server instance on the remote machine.

	.PARAMETER RemoteHostName
	Specifies the hostname of the remote machine running the remote SQL Server instance.

	.PARAMETER FQDN
	Specifies the fully qualified domain name of the Active Directory domain.

	.PARAMETER ConstrainedDelegationAllowedServices
	Specifies the services that should be allowed for constrained delegation on the SQL Server service account.

	.PARAMETER SqlSvcUsername
	Specifies the SQL Server services username.

	.PARAMETER SaPassword
	Specifies the password of the 'sa' user.
	
	.PARAMETER LocalUsername
	Specifies the local user that should have passthrough enabled.

	.PARAMETER MapAllLocalLogins
	Specifies if all the local logins should have passthrough enabled.

	.EXAMPLE
	PS> .\SqlServerPassthrough.ps1 -LinkName "MyLink" -LocalServerInstance "SQLA" -SqlSvcUsername "mydomain\sql_svca" -RemoteServerInstance "SQLB" -FQDN "mydomain.local" -SaPassword "P@ssw0rd" -LocalUsername "MYDOMAIN\jdoe"

	.EXAMPLE
	PS> .\SqlServerPassthrough.ps1 -LinkName "MyLink" -LocalServerInstance "SQLA" -ConstrainedDelegationAllowedServices "MSSQLSvc/HOSTNAMEB.mydomain.local:1433","MSSQLSvc/HOSTNAMEB:1433" -RemoteServerInstance "SQLB" -SaPassword "P@ssw0rd" -LocalUsername "MYDOMAIN\jdoe"
#>

param(
	[Parameter(Mandatory=$true)]
	[string] $LinkName,
	[Parameter(Mandatory=$true)]
	[string] $LocalServerInstance,
	[Parameter(Mandatory=$true)]
	[string] $RemoteServerInstance,
	[Parameter(Mandatory=$true)]
	[string] $RemoteHostName,
	[Parameter(Mandatory=$false)]
	[string] $FQDN,
	[Parameter(Mandatory=$false)]
	[string[]] $ConstrainedDelegationAllowedServices,
	[Parameter(Mandatory=$false)]
	[string] $SqlSvcUsername,
	[Parameter(Mandatory=$true)]
	[string] $SaPassword,
	[Parameter(Mandatory=$false)]
	[string] $LocalUsername,
	[Parameter(Mandatory=$false)]
	[switch] $MapAllLocalLogins = $false
)


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


$sqlPSDepracatedModulePath = Get-Module -ListAvailable -Name SQLPS | Select-Object -ExpandProperty Path
if ($sqlPSDepracatedModulePath)
{
	try
	{
		Write-Host "[*] Removing Depracated SQLPS Module From '$sqlPsDepracatedModulePath'..."
		Remove-Item -Recurse -Force -Path (Split-Path $sqlPSDepracatedModulePath) -ErrorAction Stop
		Write-Host "[+] Removed Depracated SQLPS Module From '$sqlPsDepracatedModulePath'."
	} catch
	{
		Write-Host "[-] Failed to remove the depracated powershell module 'SQLPS' from '$sqlPSDepracatedModulePath' - $_" -ForegroundColor Red
	}
}

# Install and load SqlServer PowerShell module
Write-Host "[*] Installing SqlServer PowerShell Module..."
$isSqlServerModuleAvailable = Get-Module -ListAvailable -Name SqlServer -ErrorAction SilentlyContinue
if (-not $isSqlServerModuleAvailable)
{
	try
	{
		Install-Module -Name SqlServer -Force -Confirm:$false	
	} catch
	{
		Write-Host "[-] Failed to install SqlServer PowerShell module - $_" -ForegroundColor Red
	}
}
Write-Host "[+] Installed SqlServer PowerShell Module."

Import-Module SqlServer

# Check if link already exists between the local instance and the remote instance
# !!!! Executing the T-SQL below requires SQL sysadmin privileges !!!!
Write-Host "[*] Checking if link '$LinkName' exists for '$LocalServerInstance' and '$RemoteHostName\$RemoteServerInstance'..." -ForegroundColor Cyan

$tsqlSelectLink = @"
SELECT 
	@@SERVERNAME AS local_instance_name,
	s.name AS link_name,
	s.data_source AS remote_instance_name
FROM sys.servers s
WHERE s.is_linked = 1
	AND @@SERVERNAME = '$LocalServerInstance'
	AND s.name = '$LinkName'
	AND s.data_source = '$RemoteHostName\$RemoteServerInstance';
"@

# Execute query to select available links
try
{
	$selectLinkQueryResult = Invoke-Sqlcmd -ServerInstance "$env:COMPUTERNAME\$LocalServerInstance" -Username "sa" -Password $SaPassword -Query $tsqlSelectLink -TrustServerCertificate -ErrorAction Stop
} catch
{
	Write-Host "[-] Failed to query available SQL Server Links - $_" -ForegroundColor Red
	exit 1
}

if ($selectLinkQueryResult.MatchCount -eq 1)
{
	Write-Host "[+] Link '$LinkName' found for '$LocalServerInstance' and '$RemoteHostName\$RemoteServerInstance'."
} elseif ($null -eq $selectLinkQueryResult.MatchCount)
{
	Write-Host "[!] Link '$LinkName' not found for '$LocalServerInstance' and '$RemoteHostName\$RemoteServerInstance'." -ForegroundColor Yellow
	Write-Host "[*] Creating link '$LinkName' for '$LocalServerInstance' and '$RemoteHostName\$RemoteServerInstance'..."
	
	# Add Link using SqlServer T-SQL
	$tsqlCreateLink = @"
IF NOT EXISTS (SELECT 1 FROM sys.servers WHERE name = N'$LinkName')
BEGIN
	EXEC sp_addlinkedserver
		@server = N'$LinkName',
		@provider = N'MSOLEDBSQL',
		@srvproduct = N'',
		@datasrc = N'$RemoteHostName\$RemoteServerInstance';
END

EXEC sp_serveroption N'$LinkName', 'rpc out', 'true';
EXEC sp_serveroption N'$LinkName', 'data access', 'true';
"@

	try
	{
		Invoke-Sqlcmd -ServerInstance "$env:COMPUTERNAME\$LocalServerInstance" -Username "sa" -Password $SaPassword -Query $tsqlCreateLink -TrustServerCertificate -ErrorAction Stop
		Write-Host "[+] Created link '$LinkName' for '$LocalServerInstance' and '$RemoteHostName\$RemoteServerInstance'." -ForegroundColor Cyan
	} catch
	{
		Write-Host "[-] Failed to create linked server - $_" -ForegroundColor Red
		exit 1
	}
} else
{
	
	Write-Host "[-] Ambiguous result. The query returned $($selectLinkQueryResult.MatchCount) links which is not 1 or 0." -ForegroundColor Red
	exit 1
}

# Add Passthrough using link
if ($MapAllLocalLogins.IsPresent)
{
	$localloginValue = "NULL"
} else
{
	$localloginValue = "N'$LocalUsername'"
}

$tsqlLogin = @"
EXEC sp_addlinkedsrvlogin
	@rmtsrvname = N'$LinkName',
	@useself = 'True',
	@locallogin = $localloginValue;
"@

try
{
	Write-Host "[*] Adding Passthrough over '$LinkName' link for '$LocalServerInstance' and '$RemoteHostName\$RemoteServerInstance'..."
	Invoke-Sqlcmd -ServerInstance "$env:COMPUTERNAME\$LocalServerInstance" -Username "sa" -Password $SaPassword -Query $tsqlLogin -TrustServerCertificate -ErrorAction Stop
	Write-Host "[+] Added Passthrough over '$LinkName' link for '$LocalServerInstance' and '$RemoteHostName\$RemoteServerInstance'."
} catch
{
	Write-Host "[-] Failed to add Passthrough over '$LinkName' link for '$LocalServerInstance' and '$RemoteHostName\$RemoteServerInstance' - $_" -ForegroundColor Red
	exit 1
}

# Enable Constrained Delegation
Write-Host "[*] Enabling Constrained Delegation for '$SqlSvcUsername'..."

$isActiveDirectoryModuleAvailable = Get-Module -ListAvailable -Name ActiveDirectory
if (-not $isActiveDirectoryModuleAvailable)
{
	Write-Host "[*] Installing RSAT-AD-PowerShell..."
	Install-WindowsFeature -Name RSAT-AD-PowerShell -IncludeAllSubFeatures
	Write-Host "[+] Installed RSAT-AD-PowerShell." 
}
Import-Module ActiveDirectory

$allowedServices = $ConstrainedDelegationAllowedServices
if ($null -eq $allowedServices)
{
	if ($FQDN -eq "")
	{
		Write-Host "[-] Failed to enable Constrained Delegation for '$SqlSvcUsername' - 'FQDN' cannot be an empty string." -ForegroundColor Red
		exit 1
	}

	try
	{
		$allowedServices = @("MSSQLSvc/$RemoteHostName.$FQDN:1433", "MSSQLSvc/$RemoteHostName:1433")	
	} catch
	{
		Write-Host "[-] Failed to enable Constrained Delegation for '$SqlSvcUsername' - $_" -ForegroundColor Red
		exit 1
	}
}

$sqlSvcUsernameHasDomainPrefix = CheckForDomainPrefix -Username $SqlSvcUsername
$isSqlSvcUsernameValid = ($SqlSvcUsername -ne "") -and ($sqlSvcUsernameHasDomainPrefix)
if (-not $isSqlSvcUsernameValid)
{
	Write-Host "[-] Failed to enable Constrained Delegation for '$SqlSvcUsername' - 'SqlSvcUsername' cannot be an empty string and should contain the domain prefix." -ForegroundColor Red
	exit 1
}

try
{
	Set-ADUser -Identity "$SqlSvcUsername" -Replace @{msDS-AllowedToDelegateTo = $allowedServices}
} catch
{
	Write-Host "[-] Failed to enable Constrained Delegation for '$SqlSvcUsername' - $_" -ForegroundColor Red
	exit 1
}

Write-Host "[+] Enabled Constrained Delegation for '$SqlSvcUsername'."

exit 0
