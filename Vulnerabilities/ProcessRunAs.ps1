<#
	.SYNOPSIS
	Modifies the Registry Autologon to force specified user logon on boot

	.DESCRIPTION
	Modifies the Registry Autologon to force specified user logon on boot

	.PARAMETER Username
	Specifies the username of the account to force logon.

	.PARAMETER Password
	Specifies the password of the account to force logon.

	.PARAMETER FQDN
	Specifies the fully qulified domain name that the user belongs to.

	.EXAMPLE
	PS> .\ProcessRunAs.ps1 -Username "MYDOMAIN\johndoe" -Password "P@ssw0rd" -FQDN "mydomain.local"

	.EXAMPLE
	PS> .\ProcessRunAs.ps1 -Username ".\johndoe" -Password "P@ssw0rd"
#>

param(
	[Parameter(Mandatory=$true)]
	[string] $Username,
	[Parameter(Mandatory=$true)]
	[string] $Password,
	[Parameter(Mandatory=$false)]
	[string] $FQDN
)

# Checks if user is in 'DOMAIN\user' format
# Does not match for local '.\user' format
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

# Match only on local '.\user' format
function CheckForLocalUserPrefix
{
	param(
		[Parameter(Mandatory=$true)]
		[string] $Username
	)
	
	if (-not ($Username -match '^\.[\\][A-Za-z0-9\s_-]+$'))
	{
		return $false
	}
	
	return $true
}

# Splits domain from username
function SplitPrefixFromUsername
{
	param(
		[Parameter(Mandatory=$true)]
		[string] $Username
	)
	
	$domain, $name = $Username.Split("\")
	return $domain, $name
}


$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

$usernameWithoutPrefix = $Username
$usernameContainsDomainPrefix = CheckForDomainPrefix -Username $Username
$isFqdnNullOrEmpty = ($null -eq $FQDN) -or ($FQDN -eq "")

if ($isFqdnNullOrEmpty -and $usernameContainsDomainPrefix)
{
	Write-Host "[-] FQDN cannot be NULL when '-Username' contains domain prefix '$Username'." -ForegroundColor Red
	exit 1
}

# Case: Install for local machine and local users
if ($isFqdnNullOrEmpty -and (-not $usernameContainsDomainPrefix))
{
	# Check the SQL service username validity
	if ((CheckForLocalUserPrefix -Username $Username))
	{
		$prefix, $usernameWithoutPrefix = SplitPrefixFromUsername -Username $Username
	}
} else
{
	$domainPrefix, $usernameWithoutPrefix = SplitPrefixFromUsername -Username $Username

	Set-ItemProperty -Path $Path -Name "DefaultDomainName" -Value $domainPrefix -Type String
}

Write-Host "[*] Modifying Registry Autologon..."

Set-ItemProperty -Path $Path -Name "AutoAdminLogon" -Value "1" -Type String
Set-ItemProperty -Path $Path -Name "ForceAutoLogon" -Value "1" -Type String
Set-ItemProperty -Path $Path -Name "DefaultUsername" -Value $usernameWithoutPrefix -Type String
Set-ItemProperty -Path $Path -Name "DefaultPassword" -Value $Password -Type String

Write-Host "[+] Modified Registry Autologon."

Write-Host "[!] Restarting computer in 5 seconds..." -ForegroundColor Yellow
Restart-Computer -Force

exit 0
