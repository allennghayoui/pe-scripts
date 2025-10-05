param (
	[Parameter(Mandatory = $true)]
	[string]$ParentDomainName,        # e.g., "corp.local"

	[Parameter(Mandatory = $true)]
	[string]$NewChildDomainName,      # e.g., "lab"

	[Parameter(Mandatory = $true)]
	[string]$ParentDCIP,              # e.g., "192.168.121.210"

	[Parameter(Mandatory = $true)]
	[string]$NewLocalAdminPassword    # e.g., "Str0ngP@ss!"
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
					$selectedNICAlias = $nic.Name
					$selectedNICLocalIP = $nic.IP
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
		$currentTask = $currentTask + 1
	}
}

######################################## Variable Declarations ########################################

# Progress
$ProgressState = @{
	CurrentTask       = 1
	TotalTasks        = 6
}

# Paths
$tempPath = "$env:TEMP"
$postRebootScriptPath = "$tempPath\PostRebootChildDomainSetup.ps1"

$domainAdminUsername = "Administrator"
$domainAdminPassword = "P@ssw0rd123!"
$securePassword = ConvertTo-SecureString $domainAdminPassword -AsPlainText -Force
$adminCred = New-Object System.Management.Automation.PSCredential($domainAdminUsername, $securePassword)
$DSRMPasswordCred = New-Object System.Management.Automation.PSCredential($domainAdminUsername, $SecurePassword)

$domainMode = "WinThreshold"

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
if ($NewChildDomainName -like "*.$ParentDomainName")
{
	Write-Warning "<USER>[!] Provided Child Domain name '$NewChildDomainName' contains the parent domain. Trimming to short name...</USER>"
	$NewChildDomainName = $NewChildDomainName -replace "\.$ParentDomainName$", ""
}
if ($NewChildDomainName -match "[^a-zA-Z0-9-]")
{
	Write-Error "<USER>[!] Invalid characters in Child Domain name '$NewChildDomainName'. Only letters, numbers, and hyphens are allowed.</USER>"
	exit 1
}

$childDomainFQDN = "$NewChildDomainName.$ParentDomainName"
$childDomainNetbiosName = $NewChildDomainName.ToUpper()

ShowProgress -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Child Domain" -CurrentOperation "Writing Post-Reboot Script..." -Id 0

Write-Host "<USER>[*] Writing Post-Reboot Script..." -ForegroundColor Cyan
$PARENT_REACHABLE_NIC = GetNICForParentDC -ParentDCIP $ParentDCIP
$NICAlias = $PARENT_REACHABLE_NIC.NICAlias
$NICLocalIP = $PARENT_REACHABLE_NIC.NICLocalIP

$POST_REBOOT_SCRIPT = @"
Start-Sleep -Seconds 15

Write-Host "<USER>[*] Configuring DNS settings...</USER>" -ForegroundColor Cyan
Set-DnsClientServerAddress -InterfaceAlias $NICAlias -ServerAddresses @($NICLocalIP, $ParentDCIP)
Write-Host "<USER>[*] Configured DNS settings.</USER>" -ForegroundColor Cyan

# Remove RunOnce registry entry
try
{
	Remove-ItemProperty -Path '$postRebootScriptRegistryEntry' -Name '$postRebootRegistryKeyName' -ErrorAction Stop
} catch
{
	Write-Error "[!] Failed to remove the RunOnce registry entry: '$RunOnceRegistryKeyName'."
	Write-Error \$_.Exception.Message
	exit 1
}
"@

$POST_REBOOT_SCRIPT | Out-File -FilePath $postRebootScriptPath -Encoding UTF8 -Force

Write-Host "<USER>[*] Post-Reboot Script Written." -ForegroundColor Cyan

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

ShowProgress -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Child Domain" -CurrentOperation "Creating Child Domain: '$childDomainFQDN'..." -Id 0

Write-Host "<USER>[*] Creating Child Domain: '$childDomainFQDN'..." -ForegroundColor Cyan
Install-ADDSDomain `
	-Credential $adminCred `
	-NewDomainName $NewChildDomainName `
	-DomainNetbiosName $childDomainNetbiosName `
	-SafeModeAdministratorPassword $DSRMPasswordCred `
	-CreateDNSDelegation `
	-DomainMode $domainMode `
	-InstallDNS `
	-NoRebootOnCompletion `
	-Confirm:$false `
	-Force
Write-Host "<USER>[*] Created Child Domain: '$childDomainFQDN'." -ForegroundColor Cyan

ShowProgress -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Child Domain" -Id 0 -Completed
