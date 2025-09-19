param(
	[Paramater(Mandatory=$true)]
	[string] $LocalServerInstance,
	[Parameter(Mandatory=$true)]
	[string] $LinkName,
	[Parameter(Mandatory=$true)]
	[string] $RemoteServerInstance,
	[Parameter(Mandatory=$true)]
	[string] $LocalUsername,
	[Parameter(Mandatory=$true)]
	[string] $RemoteSqlUsername,
	[Parameter(Mandatory=$true)]
	[string] $RemoteSqlPassword,
	[Parameter(Mandatory=$false)]
	[switch] $MapAllLocalLogins = $false
)

# Install and load SqlServer PowerShell module
Write-Host "[*] Installing SqlServer PowerShell Module..." -ForegroundColor Cyan
Install-Module -Name SqlServer

$isSqlServerModuleAvailable = Get-Module -ListAvailable -Name SqlServer -ErrorAction SilentlyContinue
if (-not $isSqlServerModuleAvailable)
{
	Write-Error "[!] SqlServer PowerShell module not found."
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

# Check if a link already exists between the local instance and the remote instance
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

$selectLinkQueryResult = Invoke-Sqlcmd -ServerInstance $LocalServerInstance -Query $tsqlSelectLink

if ($selectLinkQueryResult.MatchCount -eq 1)
{
	# Link already exists, add the credential mapping to it.
	Write-Host "[*] Link '$LinkName' found for local server instance '$LocalServerInstance' and remote server instance '$RemoteServerInstance'." -ForegroundColor Cyan
} elseif ($selectLinkQueryResult.MatchCount -eq 0)
{
	Write-Host "[*] Link '$LinkName' not found for local server instance '$LocalServerInstance' and remote server instance '$RemoteServerInstance'." -ForegroundColor Yellow
	Write-Host "[*] Creating link '$LinkName' now..." -ForegroundColor Cyan
	
	# Create new link
	$tsqlCreateLink = @"
IF NOT EXISTS (SELECT 1 FROM sys.servers WHERE name = N'$LinkName')
BEGIN
	EXEC sp_addlinkedserver
		@server = N'$LinkName',
		@srvproduct = N'SQL SERVER',
		@provider = N'SQLNCLI',
		@datasrc = N'$RemoteServerInstance';
END

EXEC sp_serveroption N'$LinkName', 'rpc out', 'True';
EXEC sp_serveroption N'$LinkName', 'data access', 'True';
"@

	try
	{
		Invoke-Sqlcmd -ServerInstance $LocalServerInstance -Query $tsqlCreateLink -ErrorAction Stop
	} catch
	{
		Write-Error "[!] Failed to create linked server."
		Write-Error $_.Exception.Message
		exit 1
	}

	Write-Host "[*] Linked server $LinkName created on $LocalServerInstance" -ForegroundColor Cyan
} else
{
	
	Write-Error "[!] Ambiguous result. The query returned $($selectLinkQueryResult.MatchCount) links which is not 1 or 0."
	exit 1
}


Write-Host "[*] Adding local login mapping to stored remote credentials..." -ForegroundColor Cyan

# Check if a user exists with the specified RemoteSqlUsername
$sqlSelectUserQuery = @"
SELECT COUNT(*) AS UserExists
FROM sys.server_principals
WHERE name = N'$RemoteSqlUsername';
"@

try
{
	$selectUserResult = Invoke-Sqlcmd -ServerInstance $RemoteServerInstance -Query $sqlSelectUserQuery -ErrorAction Stop
} catch
{
	Write-Error "[!] An error occured while checking if the $RemoteSqlUsername exists:"
	Write-Error $_.Exception.Message
	exit 1
}

if ($selectUserResult.UserExists -eq 0)
{
	Write-Error "[!] Remote user $RemoteSqlUsername does not exist on $RemoteServerInstance."
	exit 1
}

# Map local login to remote SQL credentials
$localloginValue = $MapAllLocalLogins.IsPresent ? "NULL" : "N'$LocalUsername'"

$tsqlLocalLoginMapping = @"
EXEC sp_addlinkedsrvlogin
	@rmtsrvname = N'$LinkName',
	@useself = 'False',
	@locallogin = $localloginValue,
	@rmtuser = N'$RemoteSqlUsername',
	@rmtpassword = '$RemoteSqlPassword';
"@

try
{
	Invoke-Sqlcmd -ServerInstance $LocalServerInstance -Query $tsqlLocalLoginMapping -ErrorAction Stop
} catch
{
	Write-Error "[!] An error occured while adding local login mapping to remote credentials:"
	Write-Error $_.Exception.Message
	exit 1
}

Write-Host "[+] Added local login mapping to stored remote credentials." -ForegroundColor Cyan

exit 0
