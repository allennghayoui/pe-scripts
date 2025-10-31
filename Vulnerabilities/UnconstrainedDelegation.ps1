<#
	.SYNOPSIS
	Enables Unconstrained Delegation for an account.

	.DESCRIPTION
	Enables Unconstrained Delegation for an account.

	.PARAMETER AccountName
	Specifies the account to enable Unconstrained Delegation for.

	.EXAMPLE
	PS> .\UnconstrainedDelegation.ps1 -AccountName "johndoe"
#>

param(
	[Parameter(Mandatory=$true)]
	[string] $AccountName
)

$isActiveDirectoryModuleAvailable = Get-Module -ListAvailable -Name ActiveDirectory
if (-not $isActiveDirectoryModuleAvailable)
{
	Write-Host "[*] Installing RSAT-AD-PowerShell..."
	Install-WindowsFeature -Name RSAT-AD-PowerShell -IncludeAllSubFeatures
	Write-Host "[+] Installed RSAT-AD-PowerShell." 
}
Import-Module ActiveDirectory


try
{
	Write-Host "[*] Setting Unconstrained Delegation for '$AccountName'..."
	Set-ADAccountControl -Identity $AccountName -TrustedForDelegation $true
	Write-Host "[+] Set Unconstrained Delegation for '$AccountName'."
} catch
{
	Write-Host "[-] Failed to set Unconstrained Delegation for '$AccountName' - $_" -ForegroundColor Red
	exit 1
}

exit 0
