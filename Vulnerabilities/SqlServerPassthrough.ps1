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

	.PARAMETER SaPassword
	Specifies the password of the 'sa'.
	
	.PARAMETER LocalUsername
	Specifies the local user that should have passthrough enabled.

	.PARAMETER MapAllLocalLogins
	Specifies if all the local logins should have passthrough enabled.

	.EXAMPLE
	PS> .\SqlServerPassthrough.ps1 -LinkName "MyLink" -LocalServerInstance "SQLA" -RemoteServerInstance "SQLB" -SaPassword "P@ssw0rd" -LocalUsername "MYDOMAIN\jdoe"
#>

param(
	[Parameter(Mandatory=$true)]
	[string] $LinkName,
	[Parameter(Mandatory=$true)]
	[string] $LocalServerInstance,
	[Parameter(Mandatory=$true)]
	[string] $RemoteServerInstance,
	[Parameter(Mandatory=$true)]
	[string] $SaPassword,
	[Parameter(Mandatory=$false)]
	[string] $LocalUsername,
	[Paramter(Mandtory=$false)]
	[switch] $MapAllLocalLogins = $false
)


# Install and import SqlServer PowerShell module
Write-Host "[*] Installing SqlServer PowerShell Module..."
Install-Module -Name SqlServer
Write-Host "[+] Installed SqlServer PowerShell Module."

$isSqlServerModuleAvailable = Get-Module -ListAvailable -Name SqlServer -ErrorAction SilentlyContinue
if (-not $isSqlServerModuleAvailable)
{
	Write-Host "[-] SqlServer PowerShell module not found." -ForegroundColor Red
	exit 1
}
Import-Module SqlServer

$isSqlServerModuleLoaded = (Get-Module -Name SqlServer).Name
if (-not $isSqlServerModuleLoaded)
{
	Write-Host "[-] Failed to load SqlServer PowerShell module." -ForegroundColor Red
	exit 1
}

# Check if link already exists between the local instance and the remote instance
# !!!! Executing the T-SQL below requires SQL sysadmin privileges !!!!
Write-Host "[*] Checking if link '$LinkName' exists for '$LocalServerInstance' and '$RemoteServerInstance'..." -ForegroundColor Cyan

$tsqlSelectLink = @"
SELECT 
	@@SERVERNAME AS local_instance_name,
	s.name AS link_name,
	s.data_source AS remote_instance_name
FROM sys.systems s
WHERE s.is_linked = 1
	AND @@SERVERNAME = '$LocalServerInstance'
	AND s.name = '$LinkName'
	AND s.data_source = '$RemoteServerInstance';
"@

# Execute query to select available links
try
{
	$selectLinkQueryResult = Invoke-Sqlcmd -ServerInstance "$env:COMPUTERNAME\$LocalServerInstance" -Username "sa" -Password $SaPassword -Query $tsqlSelectLink -ErrorAction Stop
} catch
{
	Write-Host "[-] Failed to query available SQL Server Links - $_" -ForegroundColor Red
	exit 1
}

if ($selectLinkQueryResult.MatchCount -eq 1)
{
	Write-Host "[+] Link '$LinkName' found for '$LocalServerInstance' and '$RemoteServerInstance'."
} elseif ($selectLinkQueryResult.MatchCount -eq 0)
{
	Write-Host "[!] Link '$LinkName' not found for '$LocalServerInstance' and '$RemoteServerInstance'." -ForegroundColor Yellow
	Write-Host "[*] Creating link '$LinkName' for '$LocalServerInstance' and '$RemoteServerInstance'..."
	
	# Add Link using SqlServer T-SQL
	$tsqlCreateLink = @"
IF NOT EXISTS (SELECT 1 FROM sys.servers WHERE name = N'$LinkName')
BEGIN
	EXEC sp_addlinkedserver
		@server = N'$LinkName',
		@srvproduct = N'SQL SERVER',
		@provider = N'SQLNCLI',
		@datasrc = N'$RemoteServerInstance';
END

EXEC sp_serveroption N'$LinkName', 'rpc out', 'true';
EXEC sp_serveroption N'$LinkName', 'data access', 'true';
"@

	try
	{
		Invoke-Sqlcmd -ServerInstance "$env:COMPUTERNAME\$LocalServerInstance" -Username "sa" -Password $SaPassword -Query $tsqlCreateLink -ErrorAction Stop
		Write-Host "[+] Created link '$LinkName' for '$LocalServerInstance' and '$RemoteServerInstance'." -ForegroundColor Cyan
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
$localloginValue = $MapAllLocalLogins.IsPresent ? "NULL" : "N'$LocalUsername'"
$tsqlLogin = @"
EXEC sp_addlinkedsrvlogin
	@rmtsrvname = N'$LinkName',
	@useself = 'True',
	@locallogin = $localloginValue;
"@

try
{
	Write-Host "[*] Adding Passthrough over '$LinkName' link for '$LocalServerInstance' and '$RemoteServerInstance'..."
	Invoke-Sqlcmd -ServerInstance "$env:COMPUTERNAME\$LocalServerInstance" -Username "sa" -Password $SaPassword -Query $tsqlLogin -ErrorAction Stop
	Write-Host "[+] Added Passthrough over '$LinkName' link for '$LocalServerInstance' and '$RemoteServerInstance'."
} catch
{
	Write-Host "[-] Failed to add Passthrough over '$LinkName' link for '$LocalServerInstance' and '$RemoteServerInstance' - $_" -ForegroundColor Red
	exit 1
}


exit 0
