param(
	[Parameter(Mandatory=$true)]
	[string] $InstanceName
)

# Install and load SqlServer PowerShell module
Write-Host "[*] Installing SqlServer PowerShell Module..."
Install-Module -Name SqlServer
Write-Host "[+] Installed SqlServer PowerShell Module."

$isSqlServerModuleAvailable = Get-Module -ListAvailable -Name SqlServer -ErrorAction SilentlyContinue
if (-not $isSqlServerModuleAvailable)
{
	Write-Error "[-] SqlServer PowerShell module not found."
	exit 1
}
Import-Module SqlServer

# Enable xp_cmdshell on target SQL Server instance
$tsqlEnableXpCmdShell = @"
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
"@

try
{
	Write-Host "[*] enabling xp_cmdshell on $InstanceName..."
	Invoke-Sqlcmd -ServerInstance $InstanceName -Database "master" -Query $tsqlEnableXpCmdShell -ErrorAction Stop
	Write-Host "[+] xp_cmdshell enabled on $InstanceName."
} catch
{
	Write-Host "[-] Failed to enable xp_cmdshell on $InstanceName - $_" -ForegroundColor Red
	exit 1
}

exit 0
