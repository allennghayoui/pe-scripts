<#
	.SYNOPSIS
	Creates a new AD Forest.

	.DESCRIPTION
	Creates a new AD Forest.

	.PARAMETER FQDN
	Specifies the Fully Qualified Domain Name of the new domain.

	.PARAMETER AdminPassword
	Specifies the Safe Mode Administrator Password.

	.EXAMPLE
	PS> .\DCNewForest.ps1 -FQDN "mydomain.local" -AdminPassword "P@ssw0rd"
#>

param(
	[Parameter(Mandatory=$true)]
	[string] $FQDN,
	[Parameter(Mandatory=$true)]
	[string] $AdminPassword
)


######################################## Function Declarations ########################################

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
		$ProgressState.CurrentTask = $ProgressState.CurrentTask + 1
	}
}

######################################## Variable Declarations ########################################

# Progress
$ProgressState = @{
	CurrentTask  = 1
	TotalTasks   = 4
}

$domainMode = "WinThreshold"
$domainPart = $FQDN -replace '^[^.]+\.',''
$domainNetbiosName = $domainPart.Split('.')[0]

$securePassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force

######################################## Script Start ########################################

# Install ADDSDeployment module
ShowProgress -Id 0 -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Child Domain" -CurrentOperation "Installing ADDSDeployment PowerShell module..."

$ADDSDeploymentModuleInstalled = Get-Module -ListAvailable -Name ADDSDeployment
if (-not ($ADDSDeploymentModuleInstalled))
{
	Write-Host "<USER>[*] Installing ADDSDeployment PowerShell module...</USER>" -ForegroundColor Cyan
	Install-Module -Name ADDSDeployment -Force
	Write-Host "<USER>[*] Installed ADDSDeployment PowerShell module.</USER>" -ForegroundColor Cyan
}
Import-Module -Name ADDSDeployment

ShowProgress -Id 0 -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Child Domain" -CurrentOperation "Creating AD Forest..."

try
{
	Write-Host "<USER>[*] Creating AD Forest...</USER>" -ForegroundColor Cyan
	Install-ADDSForest `
		-DomainName $FQDN `
		-SafeModeAdministratorPassword $securePassword `
		-DomainMode $domainMode `
		-DomainNetbiosName $domainNetbiosName `
		-InstallDNS `
		-NoRebootOnCompletion `
		-Force
	Write-Host "<USER>[*] Created AD Forest.</USER>" -ForegroundColor Cyan
} catch
{
	Write-Error "<USER>[!] Failed to create AD Forest.</USER>"
	Write-Error $_.Exception.Message
	exit 1
}

ShowProgress -Id 0 -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Child Domain" -CurrentOperation "Restarting in 5 seconds..."

Write-Warning "<USER>[*] Restarting in 5 seconds...</USER>"
Start-Sleep -Seconds 5

ShowProgress -Id 0 -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Child Domain" -Completed

Restart-Computer -Seconds 5
