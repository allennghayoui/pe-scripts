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
	TotalTasks   = 6
}

$domainMode = "WinThreshold"
$domainNetbiosName = $FQDN.Split(".")[-2]

$securePassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force

######################################## Script Start ########################################

# Install Package Provider and Set PS Repository
ShowProgress -Id 0 -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Forest" -CurrentOperation "Installing Package Provider and Setting PS Repository..."
Install-PackageProvider -Name NuGet -Force
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

# Install ADDSDeployment module
ShowProgress -Id 0 -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Forest" -CurrentOperation "Adding AD-Domain-Services Windows Feature..."

$ADDSDeploymentModuleInstalled = Get-Module -ListAvailable -Name ADDSDeployment
Write-Host "<USER>[*] Adding AD-Domain-Services Windows Feature...</USER>" -ForegroundColor Cyan
if (-not ($ADDSDeploymentModuleInstalled))
{
	Add-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
}
Write-Host "<USER>[*] Added AD-Domain-Services Windows Feature.</USER>" -ForegroundColor Cyan
Import-Module -Name ADDSDeployment

ShowProgress -Id 0 -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Forest" -CurrentOperation "Changing Administrator Password..."

try
{
	Write-Host "<USER>[*] Changing Administrator Password...</USER>" -ForegroundColor Cyan
	net user Administrator "$AdminPassword"
	Write-Host "<USER>[*] Changed Administrator Password.</USER>" -ForegroundColor Cyan
} catch
{
	Write-Error "<USER>[!] Failed to Change Administrator Password.</USER>"
	Write-Error $_.Exception.Message
	exit 1
}

ShowProgress -Id 0 -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Forest" -CurrentOperation "Creating AD Forest..."

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

ShowProgress -Id 0 -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Forest" -CurrentOperation "Restarting in 5 seconds..."

Write-Warning "<USER>[*] Restarting in 5 seconds...</USER>"
Start-Sleep -Seconds 5

ShowProgress -Id 0 -CurrentTask $ProgressState.CurrentTask -TotalTasks $ProgressState.TotalTasks -Activity "Create New AD Forest" -Completed

Restart-Computer -Force
