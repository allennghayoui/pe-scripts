param(
	[Parameter(Mandatory=$true)]
	[string] $InstanceName
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

$tsqlEnableXpCmdShell = @"
EXEC sp_configure 'show advance options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
"@

try
{
	Invoke-Sqlcmd -ServerInstance $InstanceName -Database "master" -Query $tsqlEnableXpCmdShell -ErrorAction Stop
	Write-Host "[*] xp_cmdshell enabled on $InstanceName." -ForegroundColor Cyan
} catch
{
	Write-Error "[!] Failed to enable xp_cmdshell on $InstanceName."
	Write-Error $_.Exception.Message
	exit 1
}

exit 0
