<#
	.SYNOPSIS
	Creates a new Active Directory forest.

	.DESCRIPTION
	Creates a new Active Directory forest.

	.PARAMETER DomainName
	Specifies the name of the new Active Directory forest domain.

	.PARAMETER AdminPassword
	Specifies the password corresponding to the account that will create the domain controller for any child domain. Also specifies the Administrator user's password when the computer is started in Safe Mode.

	.EXAMPLE
	.\DCNewForest.ps1 -DomainName "corp.local" -AdminPassword "Str0ngP@ss!"
#>

param (
	[Parameter(Mandatory = $true)]
	[string]$DomainName,

	[Parameter(Mandatory = $true)]
	[string]$AdminPassword
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
$totalTasks = 5
$progress = $null

# Paths
$tempPath = "$env:TEMP"
$compiledDscConfigPath = "$tempPath\ADDomain_NewForest_Config"

######################################## Script Start ########################################

# Check ActiveDirectoryDsc is installed
$progress = CalculateProgressPercentage -CurrentTask $currentTask -TotalTasks $totalTasks
Write-Host "<PROGRESS>$progress%</PROGRESS>"
Write-Progress -Activity "Setup New AD Forest" -CurrentOperation "Installing ActiveDirectoryDsc..." -Id 0 -PercentComplete $progress
$currentTask = $currentTask + 1

$isActiveDirectoryDscInstalled = Get-DscResource -Module ActiveDirectoryDsc
if (-not $isActiveDirectoryDscInstalled)
{
	Write-Host "<USER>[!] ActiveDirectoryDsc is not installed. Installing...</USER>" -ForegroundColor Cyan

	Install-Module -Name ActiveDirectoryDsc -Repository PSGallery

	if (-not $isActiveDirectoryDscInstalled)
	{
		Write-Error "<USER>[!] Failed to install ActiveDirectoryDsc.</USER>"
		exit 1
	}
}

Write-Host "<USER>[*] ActiveDirectoryDsc is installed.</USER>" -ForegroundColor Cyan

# Convert password to SecureString
$SecurePassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force

# Create PSCredential for promotion and DSRM
$AdminCred = New-Object System.Management.Automation.PSCredential("Administrator", $SecurePassword)
$DSRMPasswordCred = New-Object System.Management.Automation.PSCredential("Administrator", $SecurePassword)

# DSC Configuration to promote to new forest
Configuration ADDomain_NewForest_Config
{
	param (
		[string]$DomainNameInner,
		[PSCredential]$CredentialInner,
		[PSCredential]$DSRMPasswordInner
	)

	Import-DscResource -ModuleName ActiveDirectoryDsc

	Node "localhost" {
		ADDomain "NewForest" {
			DomainName                     = $DomainNameInner
			Credential                     = $CredentialInner
			SafemodeAdministratorPassword  = $DSRMPasswordInner
			ForestMode                     = "WinThreshold"
		}
	}
}

# Configuration data
$ConfigData = @{
	AllNodes = @(
		@{
			NodeName                    = "localhost"
			PsDscAllowPlainTextPassword = $true
		}
	)
}

# Compile and apply
$progress = CalculateProgressPercentage -CurrentTask $currentTask -TotalTasks $totalTasks
Write-Host "<PROGRESS>$progress%</PROGRESS>"
Write-Progress -Activity "Setup New AD Forest" -CurrentOperation "Compiling DSC configuration..." -Id 0 -PercentComplete $progress
$currentTask = $currentTask + 1

Write-Host "<USER>[*] Compiling DSC configuration...</USER>" -ForegroundColor Cyan
ADDomain_NewForest_Config -DomainNameInner $DomainName `
	-CredentialInner $AdminCred `
	-DSRMPasswordInner $DSRMPasswordCred `
	-ConfigurationData $ConfigData `
	-OutputPath $compiledDscConfigPath
Write-Host "<USER>[*] DSC configuration compiled.</USER>" -ForegroundColor Cyan

$progress = CalculateProgressPercentage -CurrentTask $currentTask -TotalTasks $totalTasks
Write-Host "<PROGRESS>$progress%</PROGRESS>"
Write-Progress -Activity "Setup New AD Forest" -CurrentOperation "Promoting server to new forest domain: $DomainName..." -Id 0 -PercentComplete $progress
$currentTask = $currentTask + 1

Write-Host "<USER>[*] Promoting server to new forest domain: '$DomainName'...</USER>" -ForegroundColor Cyan
Start-DscConfiguration -Path $compiledDscConfigPath -Wait -Verbose -Force
Write-Host "<USER>[*] Server promoted to new forest domain: '$DomainName'.</USER>" -ForegroundColor Cyan

# ✅ Install ADCS Certificate Authority role (after promotion)
$progress = CalculateProgressPercentage -CurrentTask $currentTask -TotalTasks $totalTasks
Write-Host "<PROGRESS>$progress%</PROGRESS>"
Write-Progress -Activity "Setup New AD Forest" -CurrentOperation "Installing ADCS Certificate Authority role..." -Id 0 -PercentComplete $progress
$currentTask = $currentTask + 1

Write-Host "<USER>[*] Installing ADCS Certificate Authority role...</USER>" -ForegroundColor Cyan
Install-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools
Start-Sleep -Seconds 10
Write-Host "<USER>[*] Installed ADCS Certificate Authority role.</USER>" -ForegroundColor Cyan

$progress = CalculateProgressPercentage -CurrentTask $currentTask -TotalTasks $totalTasks
Write-Host "<PROGRESS>$progress%</PROGRESS>"
Write-Progress -Activity "Setup New AD Forest" -CurrentOperation "Cleaning up..." -Id 0 -PercentComplete $progress
$currentTask = $currentTask + 1

Write-Host "<USER>[*] Cleaning up...</USER>" -ForegroundColor Cyan
CleanUp
Write-Host "<USER>[*] Clean up done.</USER>" -ForegroundColor Cyan

Write-Progress -Activity "Setup New AD Forest" -CurrentOperation "Installing ADCS Certificate Authority role..." -Id 0 -Completed

Write-Warning "<USER>[*] Restarting in 5 seconds...</USER>"
Start-Sleep -Seconds 5
Restart-Computer -Force
