param(
	[Parameter(Mandatory=$true)]
	[string] $LinkName,
	[Parameter(Mandatory=$true)]
	[string] $LocalServerInstance,
	[Parameter(Mandatory=$true)]
	[string] $RemoteServerInstance,
	[Parameter(Mandatory=$false)]
	[string] $LocalUsername,
	[Paramter(Mandtory=$false)]
	[switch] $MapAllLocalLogins = $false
)


# Install and import SqlServer PowerShell module
Write-Host "[*] Installing SqlServer PowerShell Module..." -ForegroundColor Cyan
Install-Module -Name SqlServer

$isSqlServerModuleAvailable = Get-Module -ListAvailable -Name SqlServer -ErrorAction SilentlyContinue
if (-not $isSqlServerModuleAvailable)
{
	Write-Error "SqlServer PowerShell module not found."
	exit 1
}

Import-Module SqlServer

$isSqlServerModuleLoaded = (Get-Module -Name SqlServer).Name
if (-not $isSqlServerModuleLoaded)
{
	Write-Error "[!] Failed to load SqlServer PowerShell module."
	exit 1
}

# Check if link already exists between the local instance and the remote instance
# !!!! Executing the T-SQL below requires SQL sysadmin privileges !!!!
Write-Host "[*] Checking if link $LinkName exists for $LocalServerInstance and $RemoteServerInstance..." -ForegroundColor Cyan

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
$selectLinkQueryResult = Invoke-Sqlcmd -ServerInstance $LocalServerInstance -Query $tsqlSelectLink

if ($selectLinkQueryResult.MatchCount -eq 1)
{
	Write-Host "[*] Link $LinkName found for $LocalServerInstance and $RemoteServerInstance." -ForegroundColor Cyan
} elseif ($selectLinkQueryResult.MatchCount -eq 0)
{
	Write-Host "[*] Link $LinkName not found for $LocalServerInstance and $RemoteServerInstance." -ForegroundColor Yellow
	Write-Host "[*] Creating link now..." -ForegroundColor Cyan
	
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
		Invoke-Sqlcmd -ServerInstance $LocalServerInstance -Query $tsqlCreateLink -ErrorAction Stop
		Write-Host "[*] Linked server $LinkName created on $sqlInstance" -ForegroundColor Cyan
	} catch
	{
		Write-Error "[!] Failed to create linked server."
		Write-Error $_.Exception.Message
		exit 1
	}
} else
{
	
	Write-Error "[!] Ambiguous result. The query returned $($selectLinkQueryResult.MatchCount) links which is not 1 or 0."
	exit 1
}

# Add Passthrough using link
Write-Host "[*] Adding 'Passthrough'..." -ForegroundColor Cyan

$localloginValue = $MapAllLocalLogins.IsPresent ? "NULL" : "N'$LocalUsername'"
$tsqlLogin = @"
EXEC sp_addlinkedsrvlogin
	@rmtsrvname = N'$LinkName',
	@useself = 'True',
	@locallogin = $localloginValue;
"@

Invoke-Sqlcmd -ServerInstance $LocalServerInstance -Query $tsqlLogin -ErrorAction Stop

Write-Host "[*] Added 'Passthrough' over $LinkName link for $LocalServerInstance and $RemoteServerInstance." -ForegroundColor Cyan

exit 0
