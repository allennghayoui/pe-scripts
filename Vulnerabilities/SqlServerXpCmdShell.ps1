<#
	.SYNOPSIS
	Enables xp_cmdshell on SQL Server.
	
	.DESCRIPTION
	Enables xp_cmdshell on the specified SQL Server instance using the 'sa' user's credentials.
	
	.PARAMETER InstanceName
	Specifies the SQL Server instance name to enable xp_cmdshell on.
	
	.PARAMETER SaPassword
	Specifies the 'sa' user's password to be used to enable xp_cmdshell.
	
	.EXAMPLE
	PS> .\SqlServerXpCmdShell.ps1 -InstanceName "SQLA" -SaPassword "Str0ngP@ss!"
#>

param(
	[Parameter(Mandatory=$true)]
	[string] $InstanceName,
	[Parameter(Mandatory=$true)]
	[string] $SaPassword
)

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
	Invoke-Sqlcmd -ServerInstance "$env:COMPUTERNAME\$InstanceName" -Database "master" -Query $tsqlEnableXpCmdShell -Username "sa" -Password $SaPassword -TrustServerCertificate -ErrorAction Stop
	Write-Host "[+] enabled xp_cmdshell on $InstanceName."
} catch
{
	Write-Host "[-] Failed to enable xp_cmdshell on $InstanceName - $_" -ForegroundColor Red
	exit 1
}

$tsqlCheckXpCmdShell = "SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';"

try
{
	Write-Host "[*] Checking if xp_cmdshell was successfully enabled..."
	$isXpCmdShellEnabled = Invoke-Sqlcmd -ServerInstance "$env:COMPUTERNAME\$InstanceName" -Database "master" -Query $tsqlCheckXpCmdShell -TrustServerCertificate -ErrorAction Stop

	if ($isXpCmdShellEnabled.value_in_use -eq 0)
	{
		Write-Host "[-] xp_cmdshell was not enabled successfully." -ForegroundColor Red
		exit 1
	}

	Write-Host "[+] xp_cmdshell successfully enabled."
} catch
{
	Write-Host "[-] Failed to check xp_cmdshell status - $_" -ForegroundColor Red
	exit 1
}

exit 0
