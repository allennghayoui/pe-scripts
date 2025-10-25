<#
	.SYNOPSIS
	Sets up SQL Server remote login vulnerability using Linked Servers.

	.DESCRIPTION
	Sets up SQL Server remote login vulnerability using Linked Servers.

	.PARAMETER LinkName
	Specifies the name of the SQL Server link.

	.PARAMETER LocalServerInstance
	Specifies the name of the SQL Server instance on the local machine.

	.PARAMETER LocalUsername
	Specifies the username of the local user that should use the remote credentials.

	.PARAMETER RemoteServerInstance
	Specifies the name of the SQL Server instance on the remote machine.

	.PARAMETER RemoteMachineFQDN
	Specifies the FQDN of the remote machine running the remote SQL Server instance.

	.PARAMETER RemoteSqlUsername
	Specifies the username of the SQL user on the remote SQL Server instance.

	.PARAMETER RemoteSqlPassword
	Specifies the password of the SQL user on the remote SQL Server instance.

	.PARAMETER SaPassword
	Specifies the password of the 'sa' user.

	.PARAMETER MapAllLocalLogins
	Specifies if all the local users should have remote login enabled.

	.EXAMPLE
	PS> .\SqlServerRemoteLogin.ps1 -LinkName "MyLink" -LocalServerInstance "SQLA" -LocalUsername "johndoe" -RemoteServerInstance "SQLB" -RemoteMachineFQDN "MACHINEB.MYDOMAIN.LOCAL" -RemoteSqlUsername "jimsmith" -RemoteSqlPassword "P@ssw0rd" -SaPassword "Str0ngP@ss!"
#>

param(
	[Parameter(Mandatory=$true)]
	[string] $LinkName,
	[Parameter(Mandatory=$true)]
	[string] $LocalServerInstance,
	[Parameter(Mandatory=$false)]
	[string] $LocalUsername,
	[Parameter(Mandatory=$true)]
	[string] $RemoteServerInstance,
	[Parameter(Mandatory=$true)]
	[string] $RemoteMachineFQDN,
	[Parameter(Mandatory=$true)]
	[string] $RemoteSqlUsername,
	[Parameter(Mandatory=$true)]
	[string] $RemoteSqlPassword,
	[Parameter(Mandatory=$true)]
	[string] $SaPassword,
	[Parameter(Mandatory=$false)]
	[switch] $MapAllLocalLogins = $false
)

# Install and load SqlServer PowerShell module
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
Write-Host "[*] Checking if link '$LinkName' exists for '$LocalServerInstance' and '$RemoteServerInstance'..."

# Check if a link already exists between the local instance and the remote instance
$tsqlSelectLink = @"
SELECT 
	@@SERVERNAME AS local_instance_name,
	s.name AS link_name,
	s.data_source AS remote_instance_name
FROM sys.servers s
WHERE s.is_linked = 1
	AND @@SERVERNAME = '$LocalServerInstance'
	AND s.name = '$LinkName'
	AND s.data_source = '$RemoteMachineFQDN\$RemoteServerInstance';
"@

try
{
	$selectLinkQueryResult = Invoke-Sqlcmd -ServerInstance "$env:COMPUTERNAME\$LocalServerInstance" -Query $tsqlSelectLink -Username "sa" -Password $SaPassword -TrustServerCertificate -ErrorAction Stop
} catch
{
	Write-Host "[-] Failed to query available SQL Server Links - $_" -ForegroundColor Red
	exit 1
}

if ($selectLinkQueryResult.MatchCount -eq 1)
{
	# Link already exists, add the credential mapping to it.
	Write-Host "[+] Link '$LinkName' found for local server instance '$LocalServerInstance' and remote server instance '$RemoteMachineFQDN\$RemoteServerInstance'."
} elseif ($null -eq $selectLinkQueryResult.MatchCount)
{
	Write-Host "[-] Link '$LinkName' not found for local server instance '$LocalServerInstance' and remote server instance '$RemoteMachineFQDN\$RemoteServerInstance'." -ForegroundColor Yellow
	Write-Host "[*] Creating link '$LinkName' now..."
	
	# Create new link
	$tsqlCreateLink = @"
IF NOT EXISTS (SELECT 1 FROM sys.servers WHERE name = N'$LinkName')
BEGIN
	EXEC sp_addlinkedserver
		@server = N'$LinkName',
		@srvproduct = N'',
		@provider = N'MSOLEDBSQL',
		@datasrc = N'$RemoteMachineFQDN\$RemoteServerInstance';
END

EXEC sp_serveroption N'$LinkName', 'rpc out', 'True';
EXEC sp_serveroption N'$LinkName', 'data access', 'True';
"@

	try
	{
		Invoke-Sqlcmd -ServerInstance "$env:COMPUTERNAME\$LocalServerInstance" -Query $tsqlCreateLink -Username "sa" -Password $SaPassword -TrustServerCertificate -ErrorAction Stop
	} catch
	{
		Write-Host "[-] Failed to create linked server - $_" -ForegroundColor Red
		exit 1
	}

	Write-Host "[+] Linked server '$LinkName' created on '$LocalServerInstance'."
} else
{
	
	Write-Host "[-] Ambiguous result. The query returned $($selectLinkQueryResult.MatchCount) number of links." -ForegroundColor Red
	exit 1
}

# Map local login to remote SQL credentials
if ($MapAllLocalLogins.IsPresent)
{
	$localloginValue = "NULL"
} else
{
	$localloginValue = "N'$LocalUsername'"
}

$tsqlLocalLoginMapping = @"
EXEC sp_addlinkedsrvlogin
	@rmtsrvname = N'$LinkName',
	@useself = 'False',
	@locallogin = $localloginValue,
	@rmtuser = N'$RemoteSqlUsername',
	@rmtpassword = N'$RemoteSqlPassword';
"@

try
{
	Invoke-Sqlcmd -ServerInstance "$env:COMPUTERNAME\$LocalServerInstance" -Query $tsqlLocalLoginMapping -Username "sa" -Password $SaPassword -TrustServerCertificate -ErrorAction Stop
} catch
{
	Write-Host "[-] Failed to add local login mapping to remote credentials - $_" -ForegroundColor Red
	exit 1
}

Write-Host "[+] Added local login mapping to stored remote credentials."

exit 0
