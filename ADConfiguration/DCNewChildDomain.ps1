<#
	.SYNOPSIS
	Creates new child domain.

	.DESCRIPTION
	Creates new child domain.

	.PARAMETER ParentDomainName
	Specifies the name of the Parent Domain.

	.PARAMETER NewChildDomainName
	Specifies the name of the new Child Domain.

	.PARAMETER ParentDCIP
	Specifies the IP address of the Domain Controller in the Parent Domain.

	.PARAMETER NewLocalAdminPassword
	Specifies the new password for the Local Administrator account.

	.EXAMPLE
	PS> .\DCNewChildDomain.ps1 -ParentDomainName "corp.local" -NewChildDomainName "lab" -ParentDCIP 192.168.121.210 -NewLocalAdminPassword "Str0ngP@ss!"
#>

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

function CalculateProgressPercentage
{
	param(
		[Parameter(Mandatory=$true)]
		[int] $CurrentTask,
		[Parameter(Mandatory=$true)]
		[int] $TotalTasks
	)

	$percentage = ($CurrentTask / $TotalTasks) * 100
	return [math]::Round($percentage, 2)
}

function CleanUp
{
	if ((Test-Path -Path $compiledDscConfigPath))
	{
		Write-Host "<USER>[*] Deleting compiled DSC configuration: '$compiledDscConfigPath'...</USER>" -ForegroundColor Cyan
		Remove-Item -Path $compiledDscConfigPath -Force -Recurse
		Write-Host "<USER>[*] Deleted compiled DSC configuration: '$compiledDscConfigPath'.</USER>" -ForegroundColor Cyan
	}
}

######################################## Variable Declarations ########################################

# Progress
$currentTask = 1
$totalTasks = 10
$progress = $null

# Paths
$tempPath = "$env:TEMP"
$compiledDscConfigPath = "$tempPath\ADDomain_NewChildDomain_Config"

######################################## Script Start ########################################

# Static domain admin credentials (hardcoded)
$DomainAdminUsername = "Administrator"
$DomainAdminPassword = "P@ssw0rd123!"

# Step 0: Change local Administrator password
try
{
	$progress = CalculateProgressPercentage -CurrentTask $currentTask -TotalTasks $totalTasks
	Write-Host "<PROGRESS>$progress%</PROGRESS>"
	Write-Progress -Activity "Setup New AD Child Domain" -CurrentOperation "Changing Local Administrator password..." -Id 0 -PercentComplete $progress
	$currentTask = $currentTask + 1

	Write-Host "<USER>[*] Changing Local Administrator password...</USER>" -ForegroundColor Cyan
	$SecureNewLocalPassword = ConvertTo-SecureString $NewLocalAdminPassword -AsPlainText -Force
	Set-LocalUser -Name "Administrator" -Password $SecureNewLocalPassword
	Write-Host "<USER>[*] Changed Local Administrator password successfully.</USER>"
} catch
{
	Write-Error "<USER>[!] Failed to change local Administrator password.</USER>"
	Write-Error $_.Exception.Message
	exit 1
}

# Convert domain admin password to SecureString
$SecurePassword = ConvertTo-SecureString $DomainAdminPassword -AsPlainText -Force
$AdminCred = New-Object System.Management.Automation.PSCredential($DomainAdminUsername, $SecurePassword)
$DSRMPasswordCred = New-Object System.Management.Automation.PSCredential("Administrator", $SecurePassword)

# 🧼 Sanitize and validate child domain name
$progress = CalculateProgressPercentage -CurrentTask $currentTask -TotalTasks $totalTasks
Write-Host "<PROGRESS>$progress%</PROGRESS>"
Write-Progress -Activity "Setup New AD Child Domain" -CurrentOperation "Validating Child Domain name..." -Id 0 -PercentComplete $progress
$currentTask = $currentTask + 1

Write-Host "<USER>[*] Validating Child Domain name...</USER>" -ForegroundColor Cyan
if ($NewChildDomainName -like "*.$ParentDomainName")
{
	Write-Warning "<USER>[!] Provided child domain name '$NewChildDomainName' contains the parent domain. Trimming to short name...</USER>"
	$NewChildDomainName = $NewChildDomainName -replace "\.$ParentDomainName$", ""
}
if ($NewChildDomainName -match '[^a-zA-Z0-9-]')
{
	Write-Error "<USER>[!] Invalid characters in child domain name '$NewChildDomainName'. Only letters, numbers, and hyphens are allowed.</USER>"
	exit 1
}

$FinalFQDN = "$NewChildDomainName.$ParentDomainName"

# Step 1: Ensure DNS tools are installed
$progress = CalculateProgressPercentage -CurrentTask $currentTask -TotalTasks $totalTasks
Write-Host "<PROGRESS>$progress%</PROGRESS>"
Write-Progress -Activity "Setup New AD Child Domain" -CurrentOperation "Installing RSAT DNS tools..." -Id 0 -PercentComplete $progress
$currentTask = $currentTask + 1

if (-not (Get-WindowsFeature RSAT-DNS-Server).Installed)
{
	Write-Host "[*] Installing RSAT DNS tools..." -ForegroundColor Cyan
	Install-WindowsFeature -Name RSAT-DNS-Server -IncludeManagementTools -ErrorAction Stop
	Write-Host "[*] Installed RSAT DNS tools." -ForegroundColor Cyan
}

# Step 2: Resolve parent DC FQDN
$progress = CalculateProgressPercentage -CurrentTask $currentTask -TotalTasks $totalTasks
Write-Host "<PROGRESS>$progress%</PROGRESS>"
Write-Progress -Activity "Setup New AD Child Domain" -CurrentOperation "Resolving parent DC FQDN..." -Id 0 -PercentComplete $progress
$currentTask = $currentTask + 1

try
{
	Write-Host "<USER>[*] Resolving parent DC FQDN...</USER>" -ForegroundColor Cyan
	$ParentFQDN = [System.Net.Dns]::GetHostEntry($ParentDCIP).HostName
	Write-Host "<USER>[*] Resolved parent DC FQDN: '$ParentFQDN'.</USER>" -ForegroundColor Cyan
} catch
{
	Write-Error "<USER>[!] Failed to resolve hostname for ${ParentDCIP}.</USER>"
	Write-Error $_.Exception.Message
	exit 1
}

# Step 3: Add conditional forwarder
# Check if DNS Windows Feature Installed
$progress = CalculateProgressPercentage -CurrentTask $currentTask -TotalTasks $totalTasks
Write-Host "<PROGRESS>$progress%</PROGRESS>"
Write-Progress -Activity "Setup New AD Child Domain" -CurrentOperation "Installing Windows Feature: 'DNS'..." -Id 0 -PercentComplete $progress
$currentTask = $currentTask + 1

Write-Host "<USER>[*] Checking Windows Feature 'DNS' installed...</USER>" -ForegroundColor Cyan

$dnsWindowsFeatureInstallState = (Get-WindowsFeature -Name DNS).InstallState
if ($dnsWindowsFeatureInstallState -ne "Installed")
{
	Write-Host "Installing Windows Feature: 'DNS'..." -ForegroundColor Cyan
	Install-WindowsFeature -Name DNS -IncludeManagementTools
	Write-Host "Installed Windows Feature: 'DNS'." -ForegroundColor Cyan
}
Import-Module DnsServer

# Check if conditional forwarder already exists
$progress = CalculateProgressPercentage -CurrentTask $currentTask -TotalTasks $totalTasks
Write-Host "<PROGRESS>$progress%</PROGRESS>"
Write-Progress -Activity "Setup New AD Child Domain" -CurrentOperation "Adding conditional forwarder for '$ParentDomainName' → $ParentDCIP..." -Id 0 -PercentComplete $progress
$currentTask = $currentTask + 1

Write-Host "<USER>[*] Adding conditional forwarder for '$ParentDomainName' → $ParentDCIP...</USER>" -ForegroundColor Cyan

$conditionalForwarder = Get-DnsServerConditionalForwarderZone -Name $ParentDomainName -ErrorAction SilentlyContinue
$conditionalForwarderContainsParentDCIP = $conditionalForwarder.MasterServers -contains $ParentDCIP

if ($conditionalForwarder -and (-not $conditionalForwarderContainsParentDCIP))
{
	Set-DnsServerConditionalForwarderZone `
		-Name $ParentDomainName `
		-MasterServers $ParentDCIP `
		-ReplicationScope "Forest"
} else
{
	try
	{
		Add-DnsServerConditionalForwarderZone `
			-Name $ParentDomainName `
			-MasterServers $ParentDCIP `
			-ReplicationScope "Forest"

	} catch
	{
		Write-Error "<USER>[!] Conditional forwarder may already exist or failed to create.</USER>"
		Write-Error $_.Exception.Message
		exit 1
	}
}

Write-Host "<USER>[*] Added conditional forwarder for '$ParentDomainName' → $ParentDCIP.</USER>" -ForegroundColor Cyan

# Step 4: Set DNS to parent DC
$progress = CalculateProgressPercentage -CurrentTask $currentTask -TotalTasks $totalTasks
Write-Host "<PROGRESS>$progress%</PROGRESS>"
Write-Progress -Activity "Setup New AD Child Domain" -CurrentOperation "Setting DNS to parent DC..." -Id 0 -PercentComplete $progress
$currentTask = $currentTask + 1

try
{
	Write-Host "<USER>[*] Setting DNS to parent DC...</USER>" -ForegroundColor Cyan

	$iface = (Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1).InterfaceAlias
	Set-DnsClientServerAddress -InterfaceAlias $iface -ServerAddresses $ParentDCIP

	Write-Host "<USER>[*] DNS configured to use parent DC at ${ParentDCIP}.</USER>"
} catch
{
	Write-Error "<USER>[!] Failed to set DNS to ${ParentDCIP}.</USER>"
	Write-Error $_.Exception.Message
	exit 1
}

# Step 5: Validate DC connectivity and advertisement
$progress = CalculateProgressPercentage -CurrentTask $currentTask -TotalTasks $totalTasks
Write-Host "<PROGRESS>$progress%</PROGRESS>"
Write-Progress -Activity "Setup New AD Child Domain" -CurrentOperation "Verifying parent DC reachability..." -Id 0 -PercentComplete $progress
$currentTask = $currentTask + 1

Write-Host "<USER>[*] Verifying parent DC reachability...</USER>"
if (-not (Test-Connection -ComputerName $ParentDCIP -Count 2 -Quiet))
{
	Write-Error "<USER>[!] Cannot ping parent domain controller at ${ParentDCIP}.</USER>"
	exit 1
}

$dcTest = nltest /dsgetdc:$ParentDomainName
if ($LASTEXITCODE -ne 0)
{
	Write-Error "[!] Parent domain controller is not advertising or unreachable."
	exit 1
}

# Step 6: Promote to child domain
Configuration ADDomain_NewChildDomain_Config
{
	param (
		[string]$ParentDomain,
		[string]$ChildName,
		[string]$FullFQDN,
		[PSCredential]$CredentialInner,
		[PSCredential]$DSRMPasswordInner
	)

	Import-DscResource -ModuleName ActiveDirectoryDsc

	Node "localhost" {
		ADDomain "NewDomainInForest" {
			DomainType                     = "ChildDomain"
			ParentDomainName               = $ParentDomain
			DomainName                     = $ChildName
			Credential                     = $CredentialInner
			SafemodeAdministratorPassword  = $DSRMPasswordInner
			DomainNetbiosName              = $ChildName.ToUpper()
		}
	}
}

# DSC Config Data
$ConfigData = @{
	AllNodes = @(
		@{
			NodeName                    = "localhost"
			PsDscAllowPlainTextPassword = $true
			PSDscAllowDomainUser        = $true
		}
	)
}

# Compile and apply
$progress = CalculateProgressPercentage -CurrentTask $currentTask -TotalTasks $totalTasks
Write-Host "<PROGRESS>$progress%</PROGRESS>"
Write-Progress -Activity "Setup New AD Child Domain" -CurrentOperation "Compiling DSC configuration for child domain: '$FinalFQDN'..." -Id 0 -PercentComplete $progress
$currentTask = $currentTask + 1

Write-Host "<USER>[*] Compiling DSC configuration for child domain: '$FinalFQDN'...</USER>"
ADDomain_NewChildDomain_Config -ParentDomain $ParentDomainName `
	-ChildName $NewChildDomainName `
	-FullFQDN $FinalFQDN `
	-CredentialInner $AdminCred `
	-DSRMPasswordInner $DSRMPasswordCred `
	-ConfigurationData $ConfigData `
	-OutputPath $compiledDscConfigPath
Write-Host "<USER>[*] Compiled DSC configuration for child domain: '$FinalFQDN'.</USER>"

$progress = CalculateProgressPercentage -CurrentTask $currentTask -TotalTasks $totalTasks
Write-Host "<PROGRESS>$progress%</PROGRESS>"
Write-Progress -Activity "Setup New AD Child Domain" -CurrentOperation "Promoting server to child domain: '$FinalFQDN'..." -Id 0 -PercentComplete $progress
$currentTask = $currentTask + 1

Write-Host "<USER>[*] Promoting server to child domain '$FinalFQDN'...</USER>"
Start-DscConfiguration -Path $compiledDscConfigPath -Wait -Verbose -Force
Start-Sleep -Seconds 10
Write-Host "<USER>[*] Promoted server to child domain '$FinalFQDN'.</USER>"

$progress = CalculateProgressPercentage -CurrentTask $currentTask -TotalTasks $totalTasks
Write-Host "<PROGRESS>$progress%</PROGRESS>"
Write-Progress -Activity "Setup New AD Child Domain" -CurrentOperation "Cleaning up..." -Id 0 -PercentComplete $progress
$currentTask = $currentTask + 1

Write-Host "<USER>[*] Cleaning up...</USER>" -ForegroundColor Cyan
CleanUp
Write-Host "<USER>[*] Clean up done.</USER>" -ForegroundColor Cyan

Write-Progress -Activity "Setup New AD Child Domain" -Id 0 -Completed

Write-Warning "<USER>[!] Restarting in 5 seconds...</USER>"
Start-Sleep -Seconds 5
Restart-Computer -Force
