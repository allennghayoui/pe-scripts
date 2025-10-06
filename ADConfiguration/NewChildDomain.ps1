<#
	.SYNOPSIS
	Creates a new AD Child Domain.

	.DESCRIPTION
	Creates a new AD Child Domain.

	.PARAMETER ParentDomainFQDN
	Specifies the AD Parent Domain Fully Qualified Domain Name.

	.PARAMETER NewChildDomainName
	Specifies the new AD Child Domain name.

	.PARAMETER ParentDCIP
	Specifies the Parent Domain's Domain Controller IP.

	.PARAMETER DomainAdminUsername
	Specifies username of the Domain Administrator.

	.PARAMETER DomainAdminPassword
	Specifies password of the Domain Administrator.

	.PARAMETER ChildDomainAdminPassword
	Specifies the SafeModeAdministrator and the Local Administrator password for the new AD Child Domain.

	.EXAMPLE
	PS> .\DCNewChildDomain.ps1 -ParentDomainFQDN "mydomain.local" -NewChildDomainName "lab" -ParentDCIP "172.31.9.89" -DomainAdminUsername "MYDOMAIN\Administrator" -DomainAdminPassword "P@ssw0rd" -ChildDomainAdminPassword "Str0ngP@ss!"
#>


param (
	[Parameter(Mandatory = $true)]
	[string] $ParentDomainFQDN,
	[Parameter(Mandatory = $true)]
	[string] $NewChildDomainName,
	[Parameter(Mandatory = $true)]
	[string] $ParentDCIP,
	[Parameter(Mandatory=$true)]
	[string] $DomainAdminUsername,
	[Parameter(Mandatory=$true)]
	[string] $DomainAdminPassword,
	[Parameter(Mandatory=$true)]
	[string] $ChildDomainAdminPassword
)

######################################## Function Declarations ########################################

function GetNICForParentDC
{
	param(
		[Parameter(Mandatory=$true)]
		[string] $ParentDCIP
	)

	# Get all active NICs
	$activeNICs = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

	$selectedNICAlias = $null
	$selectedNICLocalIP = $null
	foreach ($nic in $activeNICs)
	{
		$IPAddresses = Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress

		foreach ($IP in $IPAddresses)
		{
			try
			{
				$result = Test-NetConnection -ComputerName $ParentDCIP -Port 53 -WarningAction SilentlyContinue
				if ($result.TcpTestSucceeded -or $result.PingSucceeded)
				{
					$selectedNICAlias = $result.InterfaceAlias
					$selectedNICLocalIP = $result.RemoteAddress.IPAddressToString
					break
				}
			} catch
			{
				continue
			}
		}
		if ($selectedNICAlias -and $selectedNICLocalIP)
		{ 
			break 
		}
	}

	if ((-not $selectedNICAlias) -or (-not $selectedNICLocalIP))
	{
		Write-Error "[!] Failed to find NIC that can reach the Parent Domain DC at $ParentDCIP"
		exit 1
	}

	Write-Host "[*] Selected NIC for parent DC with alias '$selectedNICAlias' and IP '$selectedNICLocalIP'." -ForegroundColor Cyan

	return [PSCustomObject]@{
		NICAlias = $selectedNICAlias
		NICLocalIP = $selectedNICLocalIP
	}
}

function ShowProgress
{
	param(
		[Parameter(Mandatory=$true)]
		[string] $Activity,
		[Parameter(Mandatory=$false)]
		[string] $CurrentOperation,
		[Parameter(Mandatory=$true)]
		[int] $Id,
		[Parameter(Mandatory=$true)]
		[string] $CurrentTask,
		[Parameter(Mandatory=$true)]
		[string] $TotalTasks,
		[Parameter(Mandatory=$false)]
		[switch] $Completed
	)

	if ($Completed.IsPresent)
	{
		Write-Progress -Activity $Activity -Id $Id -Completed
	} else
	{
		$percentage = ($CurrentTask / $TotalTasks) * 100
		$progress = [math]::Round($percentage)

		Write-Host "<PROGRESS>$progress%</PROGRESS>"
		Write-Progress -Activity $Activity -CurrentOperation $CurrentOperation -Id $Id -PercentComplete $progress
		$PrgressState.CurrentTask = $ProgressState.CurrentTask + 1
	}
}

######################################## Variable Declarations ########################################

# Progress
$ProgressState = @{
	CurrentTask       = 1
	TotalTasks        = 15
}

# Paths
$tempPath = "$env:TEMP"
$postRebootScriptPath = "$tempPath\PostRebootChildDomainSetup.ps1"
$postRebootProgressStatePath = "$tempPath\PostRebootProgressState.json"

# Domain Creds
$secureParentDomainAdminPassword = ConvertTo-SecureString $DomainAdminPassword -AsPlainText -Force
$secureChildDomainAdminPassword = ConvertTo-SecureString $ChildDomainAdminPassword -AsPlainText -Force
$parentDomainAdminCreds = New-Object System.Management.Automation.PSCredential($DomainAdminUsername, $secureParentDomainAdminPassword)

$domainType = "ChildDomain"

$postRebootScriptRegistryEntry = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
$postRebootRegistryKeyName = "PostRebootChildDomainSetup"

######################################## Script Start ########################################

# Install ADDSDeployment module
ShowProgress -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Child Domain" -CurrentOperation "Installing ADDSDeployment PowerShell module..." -Id 0

$ADDSDeploymentModuleInstalled = Get-Module -ListAvailable -Name ADDSDeployment
Write-Host "<USER>[*] Installing ADDSDeployment PowerShell module..." -ForegroundColor Cyan
if (-not ($ADDSDeploymentModuleInstalled))
{
	Install-Module -Name ADDSDeployment -Force
}
Write-Host "<USER>[*] Installed ADDSDeployment PowerShell module." -ForegroundColor Cyan
Import-Module ADDSDeployment

# Validate Child Domain
ShowProgress -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Child Domain" -CurrentOperation "Validating Child Domain Name..." -Id 0

Write-Host "<USER>[*] Validating Child Domain name...</USER>" -ForegroundColor Cyan
if ($NewChildDomainName -like "*.$ParentDomainFQDN")
{
	Write-Warning "<USER>[!] Provided Child Domain name '$NewChildDomainName' contains the parent domain. Trimming to short name...</USER>"
	$NewChildDomainName = $NewChildDomainName -replace "\.$ParentDomainFQDN$", ""
}
if ($NewChildDomainName -match "[^a-zA-Z0-9-]")
{
	Write-Error "<USER>[!] Invalid characters in Child Domain name '$NewChildDomainName'. Only letters, numbers, and hyphens are allowed.</USER>"
	exit 1
}

$childDomainFQDN = "$NewChildDomainName.$ParentDomainFQDN"

ShowProgress -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Child Domain" -CurrentOperation "Writing Post-Reboot Script..." -Id 0

Write-Host "<USER>[*] Writing Post-Reboot Script..." -ForegroundColor Cyan
$PARENT_REACHABLE_NIC = GetNICForParentDC -ParentDCIP $ParentDCIP
$NICAlias = $PARENT_REACHABLE_NIC.NICAlias
$NICLocalIP = $PARENT_REACHABLE_NIC.NICLocalIP

$POST_REBOOT_SCRIPT = @"
function ShowProgress
{
	param(
		[Parameter(Mandatory=$true)]
		[string] `$Activity,
		[Parameter(Mandatory=$false)]
		[string] `$CurrentOperation,
		[Parameter(Mandatory=$true)]
		[int] `$Id,
		[Parameter(Mandatory=$true)]
		[string] `$CurrentTask,
		[Parameter(Mandatory=$true)]
		[string] `$TotalTasks,
		[Parameter(Mandatory=$false)]
		[switch] `$Completed
	)

	if (`$Completed.IsPresent)
	{
		Write-Progress -Activity `$Activity -Id `$Id -Completed
	} else
	{
		`$percentage = (`$CurrentTask / `$TotalTasks) * 100
		`$progress = [math]::Round(`$percentage)

		Write-Host "<PROGRESS>`$progress%</PROGRESS>"
		Write-Progress -Activity `$Activity -CurrentOperation `$CurrentOperation -Id `$Id -PercentComplete `$progress
		`$currentTask = `$currentTask + 1
	}
}

`$ProgressState = Get-Content $postRebootProgressStatePath | ConvertFrom-Json

Start-Sleep -Seconds 15

ShowProgress -CurrentTask `$ProgressState.CurrentTask -TotalTasks `$ProgressState.TotalTasks -Activity "Create New AD Child Domain" -CurrentOperation "Configurating DNS..." -Id 0

Write-Host "<USER>[*] Configuring DNS settings...</USER>" -ForegroundColor Cyan
Set-DnsClientServerAddress -InterfaceAlias $NICAlias -ServerAddresses @($NICLocalIP, $ParentDCIP)
Write-Host "<USER>[*] Configured DNS settings.</USER>" -ForegroundColor Cyan

ShowProgress -CurrentTask `$ProgressState.CurrentTask -TotalTasks `$ProgressState.TotalTasks -Activity "Create New AD Child Domain" -CurrentOperation "Removing Registry Key For Post-Reboot Script..." -Id 0

# Remove RunOnce registry entry
try
{
	Write-Host "<USER>[*] Removing Registry Key for Post-Reboot Script...</USER>" -ForegroundColor Cyan
	Remove-ItemProperty -Path '$postRebootScriptRegistryEntry' -Name '$postRebootRegistryKeyName' -ErrorAction Stop
	Write-Host "<USER>[*] Removed Registry Key for Post-Reboot Script.</USER>" -ForegroundColor Cyan
} catch
{
	Write-Error "[!] Failed to remove the RunOnce registry entry: '$RunOnceRegistryKeyName'."
	Write-Error \$_.Exception.Message
	exit 1
}

try
{
	Write-Host "<USER>[*] Removing post-reboot script file: '$postRebootScriptPath'...</USER>" -ForegroundColor Cyan
	Remove-Item -Path $postRebootScriptPath -Force
	Write-Host "<USER>[*] Removed post-reboot script file: '$postRebootScriptPath'.</USER>" -ForegroundColor Cyan
} catch
{
	Write-Error "<USER>[!] Failed to remove post-reboot script file: '$postRebootScriptPath'.</USER>"
	Write-Error \$_.Exception.Message
	exit 1
}

try
{
	Write-Host "[*] Removing post-reboot progress state file: '$postRebootProgressStatePath'..." -ForegroundColor Cyan
	Remove-Item -Path $postRebootProgressStatePath -Force
	Write-Host "[*] Removed post-reboot progress state file: '$postRebootProgressStatePath'." -ForegroundColor Cyan
} catch
{
	Write-Error "[!] Failed to remove post-reboot script file: '$postRebootProgressStatePath'."
	Write-Error \$_.Exception.Message
	exit 1
}

ShowProgress -CurrentTask `$ProgressState.CurrentTask -TotalTasks `$ProgressState.TotalTasks -Activity "Create New AD Child Domain" -Completed
"@

$POST_REBOOT_SCRIPT | Out-File -FilePath $postRebootScriptPath -Encoding UTF8 -Force

Write-Host "<USER>[*] Post-Reboot Script Written.</USER>" -ForegroundColor Cyan

ShowProgress -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Child Domain" -CurrentOperation "Creating Registry Key For Post-Reboot Script..." -Id 0

Write-Host "[*] Creating Registry Key For Post-Reboot Script..." -ForegroundColor Cyan
try
{
	New-ItemProperty -Path $postRebootScriptRegistryEntry `
		-Name $postRebootRegistryKeyName `
		-Value "powershell.exe -ExecutionPolicy Bypass -File `"$postRebootScriptPath`"" `
		-PropertyType String `
		-Force
} catch
{
	Write-Error "[!] Failed to create registry entry: '$postRebootRegistryKeyName'..."
	Write-Error $_.Exception.Message
	exit 1
}
Write-Host "[*] Created Registry Key For Post-Reboot Script..." -ForegroundColor Cyan

ShowProgress -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Child Domain" -CurrentOperation "Setting DNS to Parent Temporarily..." -Id 0

try
{
	Write-Host "<USER>[*] Setting DNS to Parent Temporarily...</USER>" -ForegroundColor Cyan
	Set-DnsClientServerAddress -InterfaceAlias $NICAlias -ServerAddresses @($ParentDCIP)
	Write-Host "<USER>[*] Setting DNS to Parent Temporarily.</USER>" -ForegroundColor Cyan
} catch
{
	Write-Error "<USER>[!] Failed Setting DNS to Parent.</USER>"
	Write-Error $_.Exception.Message
	exit 1
}

ShowProgress -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Child Domain" -CurrentOperation "Flushing DNS..." -Id 0

try
{
	Write-Host "<USER>[*] Flushing DNS...</USER>" -ForegroundColor Cyan
	ipconfig /flushdns
	Write-Host "<USER>[*] Flushed DNS.</USER>" -ForegroundColor Cyan
} catch
{
	Write-Error "<USER>[!] Failed to flush DNS.</USER>"
	Write-Error $_.Exception.Message
	exit 1
}

ShowProgress -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Child Domain" -CurrentOperation "Testing DNS Connection to Parent DC..." -Id 0

try
{
	Write-Host "<USER>[*] Testing DNS Connection to Parent DC...</USER>" -ForegroundColor Cyan
	Resolve-DnsName $ParentDomainFQDN -ErrorAction Stop
	Write-Host "<USER>[*] Successfully Tested DNS Connection to Parent DC.</USER>" -ForegroundColor Cyan
} catch
{
	Write-Error "<USER>[!] Failed testing DNS connection to Parent DC.</USER>"
	Write-Error $_.Exception.Message
	exit 1
}

ShowProgress -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Child Domain" -CurrentOperation "Changing Child Domain Administrator Password..." -Id 0

try
{
	Write-Host "<USER>[*] Changing Child Domain Administrator Password...</USER>" -ForegroundColor Cyan
	net user Administrator "$ChildDomainAdminPassword"
	Write-Host "<USER>[*] Changed Child Domain Administrator Password.</USER>" -ForegroundColor Cyan
} catch
{
	Write-Error "<USER>[!] Failed to Change Child Domain Administrator Password.</USER>"
	Write-Error $_.Exception.Message
	exit 1
}

ShowProgress -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Child Domain" -CurrentOperation "Creating Child Domain: '$childDomainFQDN'..." -Id 0

Write-Host "<USER>[*] Creating Child Domain: '$childDomainFQDN'..." -ForegroundColor Cyan
try
{
	Install-ADDSDomain `
		-Credential $parentDomainAdminCreds `
		-NewDomainName $NewChildDomainName `
		-ParentDomainFQDN $ParentDomainFQDN `
		-SafeModeAdministratorPassword $secureChildDomainAdminPassword `
		-DomainType $domainType `
		-CreateDNSDelegation `
		-InstallDNS `
		-NoRebootOnCompletion `
		-Force
} catch
{
	Wite-Error "[!] Failed to Create Child Domain: $'$childDomainFQDN'."
	Write-Error $_.Exception.Message
	exit 1
}
Write-Host "<USER>[*] Created Child Domain: '$childDomainFQDN'." -ForegroundColor Cyan


ShowProgress -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Child Domain" -CurrentOperation "Saving Progress State to '$postRebootProgressStatePath'..." -Id 0 -Completed

Write-Host "[*] Saving Post-Reboot Progress State to '$postRebootProgressStatePath'..." -ForegroundColor Cyan
$ProgressState | ConvertTo-Json | Out-File $postRebootProgressStatePath
Write-Host "[*] Saved Post-Reboot Progress State to '$postRebootProgressStatePath'..." -ForegroundColor Cyan

ShowProgress -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Child Domain" -CurrentOperation "Restarting machine..." -Id 0 -Completed

Write-Warning "<USER>Restarting the machine for the changes to take effect...</USER>"
Restart-Computer -Force
