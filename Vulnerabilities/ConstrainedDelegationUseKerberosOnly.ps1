<#
	.SYNOPSIS
	Enables constrained delegation (Use Kerberos only) for a specified account.

	.DESCRIPTION
	Enables constrained delegation (Use Kerberos only) for a specified account.

	.PARAMETER AccountName
	Specifies the name of the account to enable constrained delegation for.

	.EXAMPLE
	PS> .\ConstrainedDelegationUseKerberosOnly.ps1 -AccountName "johndoe"
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
	Write-Host "[*] Fetching AD account object for '$AccountName'..."
	$accountObject = Get-ADObject -Filter { SamAccountName -eq $AccountName } -Properties msDSAllowedToDelegateTo, userAccountControl
	Write-Host "[+] Fetched AD account object for '$AccountName'."
} catch
{
	Write-Host "[-] Failed to fetch account object - $_" -ForegroundColor Red
	exit 1
}

if (-not $accountObject)
{
	Write-Host "[-] Account '$AccountName' does not exist." -ForegroundColor Red
	exit 1
}

# Set the TRUSTED_FOR_DELEGATION bit (0x80000 = 524288)
$uac = $accountObject.userAccountControl -bor 0x80000

try
{
	Write-Host "[*] Setting TRUSTED_FOR_DELEGATION bit for '$AccountName'..."
	Set-ADObject -Identity $accountObject.DistinguishedName -Replace @{ userAccountControl = $uac }
	Write-Host "[+] Set TRUSTED_TO_AUTH_FOR_DELEGATION bit for '$AccountName'."
} catch
{
	Write-Host "[-] Failed to set TRUSTED_TO_AUTH_FOR_DELEGATION bit for '$AccountName' - $_" -ForegroundColor Red
	exit 1
}

exit 0
