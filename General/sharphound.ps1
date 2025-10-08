<#
	.SYNOPSIS
	Installs and runs the Sharphound data collector.

	.DESCRIPTION
	Installs the Sharphound data collector from a running Bloodhound instance and runs a scan querying all the domain info and writes them to the console.

	.EXAMPLE
	PS> .\sharphound.ps1
#>


######################################## Function Declarations ########################################

function ManageWindowsProtection
{
	param(
		[Parameter(Mandatory=$false)]
		[switch] $Disable,
		[Parameter(Mandatory=$false)]
		[switch] $Reset
	)
	
	if ($Disable.IsPresent)
	{
		Write-Warning "[*] Disabling Realtime Monitoring..."
		# Disable Realtime Monitoring for threats
		Set-MpPreference -DisableRealtimeMonitoring $true
		Write-Warning "[*] Realtime Monitoring disabled."

		Write-Warning "[*] Disabling MAPSReporting Active Protection..."
		# Specifies the type of membership in the Microsoft Active Protection Service
		# Value = 0 (Disabled)
		Set-MpPreference -MAPSReporting 0
		Write-Warning "[*] MAPSReporting Active Protection disabled."

		Write-Warning "[*] Revoking consent for Sample Submission..."
		# Specifies user consent for sending samples.
		# Value = 2 (Never send)
		Set-MpPreference -SubmitSamplesConsent 2
		Write-Warning "[*] Revoked consent for Sample Submission."

		Write-Warning "[*] Windows Virus and Threat Protection has been disabled temporarily."
		
		return $null
	}
	
	if ($Reset.IsPresent)
	{
		# Reset Windows Virtus and Threat Protection
		Write-Warning "[*] Re-enabling Windows Protection..."

		# Reset Realtime Monitoring for threats
		Write-Warning "[*] Resetting Realtime Monitoring..."
		Set-MpPreference -DisableRealtimeMonitoring $realtimeMonitoringOriginal
		Write-Warning "[*] Realtime Monitoring reset."

		# Specifies the type of membership in the Microsoft Active Protection Service
		Write-Warning "[*] Resetting MAPSReporting Active Protection..."
		Set-MpPreference -MAPSReporting $mapsReportingOriginal
		Write-Warning "[*] MAPSReporting Active Protection reset."

		# Specifies user consent for sending samples.
		Write-Warning "[*] Resetting consent for Sample Submission..."
		Set-MpPreference -SubmitSamplesConsent $submitSamplesConsentOriginal
		Write-Warning "[*] Reset consent for Sample Submission."

		Write-Warning "[*] Windows Virus and Threat Protection has been reset."
		
		return $null
	}

	Write-Error "[!] Ambiguous option. You can only select one of -Disable OR -Reset"
	return $null
}

function RemoveSharphoundZip
{
	if ((Test-Path -Path $sharphoundZipPath))
	{
		try
		{
			Write-Host "[*] Deleting '$sharphoundZipPath'..." -ForegroundColor Cyan
			Remove-Item -Path $sharphoundZipPath -Force -ErrorAction Stop
			Write-Host "[*] Deleted '$sharphoundZipPath'." -ForegroundColor Cyan
		} catch
		{
			Write-Error $_.Exception.Message
			exit 1
		}
	}
}

function RemoveSharphoundFolder
{
	if ((Test-Path -Path $sharphoundPath))
	{
		try
		{
			Write-Host "[*] Deleting '$sharphoundPath'..." -ForegroundColor Cyan
			Remove-Item -Path $sharphoundPath -Force -Recurse -ErrorAction Stop
			Write-Host "[*] Deleted '$sharphoundPath'." -ForegroundColor Cyan
		} catch
		{
			Write-Error $_.Exception.Message
			exit 1
		}
	}
}

function RemoveSharphoundResultsFolder
{
	if ((Test-Path -Path $sharphoundResultsPath))
	{
		try
		{
			Write-Host "[*] Deleting '$sharphoundResultsPath'..." -ForegroundColor Cyan
			Remove-Item -Path $sharphoundResultsPath -Force -Recurse -ErrorAction Stop
			Write-Host "[*] Deleted '$sharphoundResultsPath'." -ForegroundColor Cyan
		} catch
		{
			Write-Error $_.Exception.Message
			exit 1
		}
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
		[Parameter(Mandatory=$false)]
		[Hashtable] $ProgressState,
		[Parameter(Mandatory=$false)]
		[switch] $Completed
	)

	$argsList = @{
		Activity = $Activity
		Id = $Id
	}

	$percentage = ($ProgressState.CurrentTask / $ProgressState.TotalTasks) * 100
	$progress = [math]::Round($percentage)
	Write-Host "<PROGRESS>$progress%</PROGRESS>"

	if ($Completed.IsPresent)
	{
		Write-Progress @argsList -Completed
	} else
	{
		$argsList.CurrentOperation = $CurrentOperation
		$argsList.PercentComplete = $progress

		Write-Progress @argsList

		$ProgressState.CurrentTask = $ProgressState.CurrentTask + 1
	}
}

######################################## Variable Declarations ########################################

# Progress
$ProgressState = @{
	CurrentTask = 1
	TotalTasks =  11
}

# Paths
$tempPath = "$env:TEMP"
$sharphoundZipPath = "$tempPath\sharphound.zip"
$sharphoundPath = "$tempPath\sharphound"
$sharphoundResultsPath = "$tempPath\SharphoundResults"
$sharphoundZipFiles = "$sharphoundResultsPath\ZipFiles"
$sharphoundJsonFiles = "$sharphoundResultsPath\JSONFiles"
$sharphoundExePath = "$sharphoundPath\Sharphound.exe"

# Windows Protection Original values
$realtimeMonitoringOriginal = (Get-MpPreference).DisableRealtimeMonitoring
$mapsReportingOriginal = (Get-MpPreference).MAPSReporting
$submitSamplesConsentOriginal = (Get-MpPreference).SubmitSamplesConsent

######################################## Script Start ########################################

# Task 1: Disable Windows Virtus and Threat Protection
ShowProgress -Id 0 -ProgressState $ProgressState -Activity "Sharphound Installation and Scan" -CurrentOperation "Disabling Windows Protection Temporarily..."

Write-Warning "[*] Downloading/Running Sharphound requires Windows Protection to be disabled temporarily..."

ManageWindowsProtection -Disable

# Task 2: Download Sharphound Archive
ShowProgress -Id 0 -ProgressState $ProgressState -Activity "Sharphound Installation and Scan" -CurrentOperation "Downloading the Sharphound Archive..."

try
{
	Write-Host "[*] Downloading the Sharphound archive..." -ForegroundColor Cyan

	Invoke-RestMethod -Uri "https://github.com/SpecterOps/SharpHound/releases/download/v2.7.2/SharpHound_v2.7.2_windows_x86.zip" -Outfile $sharphoundZipPath -ErrorAction Stop

	Write-Host "[*] Downloaded Sharphound into $sharphoundZipPath." -ForegroundColor Cyan
} catch
{
	Write-Error "[!] Download Failed"
	Write-Error $_.Exception.Message
	
	ManageWindowsProtection -Reset
	
	exit 1
}

# Task 3: Extract Downloaded Sharphound Archive
ShowProgress -Id 0 -ProgressState $ProgressState -Activity "Sharphound Installation and Scan" -CurrentOperation "Extracting Sharphound Archive..."

try
{
	Write-Host "[*] Extracting $sharphoundZipPath..." -ForegroundColor Cyan

	Expand-Archive -Path $sharphoundZipPath $sharphoundPath -Force -ErrorAction Stop

	Write-Host "[*] Extracted $sharphoundZipPath into $sharphoundPath." -ForegroundColor Cyan
} catch
{
	Write-Error "[!] Error extrating $sharphoundZipPath."
	Write-Error $_.Exception.Message
	
	RemoveSharphoundZip
	
	ManageWindowsProtection -Reset
	
	exit 1
}

# Task 4: Create Directories for Sharphound Results
ShowProgress -Id 0 -ProgressState $ProgressState -Activity "Sharphound Installation and Scan" -CurrentOperation "Creating Directory for Sharphound Results..."

try
{
	Write-Host "[*] Creating Sharphound results directory '$sharphoundResultsPath'..." -ForegroundColor Cyan
	New-Item -Path $sharphoundResultsPath -ItemType Directory -Force -ErrorAction Stop
	Write-Host "[*] Created Sharphound results directory '$sharphoundResultsPath'." -ForegroundColor Cyan
	
	Write-Host "[*] Creating Sharphound zip files directory '$sharphoundZipFiles'..." -ForegroundColor Cyan
	New-Item -Path $sharphoundZipFiles -ItemType Directory -Force -ErrorAction Stop
	Write-Host "[*] Created Sharphound results directory '$sharphoundZipFiles'." -ForegroundColor Cyan
	
	Write-Host "[*] Creating Sharphound results directory '$sharphoundJsonFiles'..." -ForegroundColor Cyan
	New-Item -Path $sharphoundJsonFiles -ItemType Directory -Force -ErrorAction Stop
	Write-Host "[*] Created Sharphound results directory '$sharphoundJsonFiles'." -ForegroundColor Cyan
} catch
{
	Write-Error "[!] Failed to create directory: '$sharphoundResultsPath'."
	Write-Error $_.Exception.Message
	
	RemoveSharphoundZip
	
	exit 1
}

# Task 5: Run Sharphound Scan
ShowProgress -Id 0 -ProgressState $ProgressState -Activity "Sharphound Installation and Scan" -CurrentOperation "Running Sharphound Scan..."

try
{
	Write-Host "[*] Running Sharphound..." -ForegroundColor Cyan

	Start-Process -Wait -FilePath $sharphoundExePath -ArgumentList "-c All --OutputDirectory $sharphoundZipFiles" -ErrorAction Stop

	$zipResultFiles = Get-ChildItem -Path $sharphoundZipFiles -Filter "*_Bloodhound.zip"

	Write-Host "[*] Sharphound scan is done. The results are contained in the following zip files: $($zipResultFiles.Name -join ', ')" -ForegroundColor Cyan
} catch
{
	Write-Error "[!] Error running Sharphound."
	Write-Error $_.Exception.Message
	
	RemoveSharphoundZip
	RemoveSharphoundFolder
	RemoveSharphoundResultsFolder
	
	ManageWindowsProtection -Reset
	
	exit 1
}

# Task 6: Reset Windows Protection to Previous State
ShowProgress -Id 0 -ProgressState $ProgressState -Activity "Sharphound Installation and Scan" -CurrentOperation "Resetting Windows Protection to Previous State..."

# Reset Windows Protection
ManageWindowsProtection -Reset

# Task 7: Create New Directory to Store JSON Results
ShowProgress -Id 0 -ProgressState $ProgressState -Activity "Sharphound Installation and Scan" -CurrentOperation "Creating new directory to store JSON results..."

try
{
	Write-Host "[*] Creating new directory to store JSON results..." -ForegroundColor Cyan
	New-Item -Path $sharphoundJsonFiles -ItemType Directory -Force -ErrorAction Stop
	Write-Host "[*] Created new directory to store JSON results." -ForegroundColor Cyan
} catch
{
	Write-Error "[!] Failed to create new directory to store JSON results."
	Write-Error $_.Exception.Message
		
	RemoveSharphoundZip
	RemoveSharphoundFolder
	RemoveSharphoundResultsFolder

	exit 1
}

# Task 8: Extract Result Files into New Directory
ShowProgress -Id 0 -ProgressState $ProgressState -Activity "Sharphound Installation and Scan" -CurrentOperation "Extracting result files into new directory: '$sharphoundJsonFiles'..."

Write-Host "[*] Extracting result files into new directory: '$sharphoundJsonFiles'..." -ForegroundColor Cyan

foreach ($result in $zipResultFiles)
{
	try
	{
		Write-Host "[*] Extracting '$result'..." -ForegroundColor Cyan

		Expand-Archive -Path "$sharphoundZipFiles\$result" -DestinationPath "$sharphoundJsonFiles" -Force -ErrorAction Stop

		Write-Host "[*] Extracted '$result'." -ForegroundColor Cyan
	} catch
	{
		Write-Error "[!] Failed to extract '$result'."
		Write-Error $_.Exception.Message
		
		RemoveSharphoundZip
		RemoveSharphoundFolder
		RemoveSharphoundResultsFolder
		
		exit 1
	}
}
Write-Host "[*] Extracted result files into new directory: '$sharphoundJsonFiles'." -ForegroundColor Cyan

# Task 9: Write JSON File Content to Console
ShowProgress -Id 0 -ProgressState $ProgressState -Activity "Sharphound Installation and Scan" -CurrentOperation "Writing JSON file content to console..."

Write-Host "[*] Writing content of JSON files to console..." -ForegroundColor Cyan

$jsonResultFiles = Get-ChildItem -Path $sharphoundJsonFiles -Filter "*.json"
$jsonResultFilesCount = $jsonResultFiles.Length
$currentJsonResultFile = 1

Write-Host "<TOTALFILES>$jsonResultFilesCount</TOTALFILES>" -ForegroundColor Cyan

foreach ($jsonFile in $jsonResultFiles)
{
	try
	{
		Write-Host "[*] Writting '$jsonFile' to console..." -ForegroundColor Cyan

		$fileContent = Get-Content -Path "$sharphoundJsonFiles\$jsonFile"
		Write-Host "<FILE $currentJsonResultFile/$jsonResultFilesCount>$fileContent</FILE $currentJsonResultFile/$jsonResultFilesCount>" -ForegroundColor Cyan

		Write-Host "[*] Written '$jsonFile' to console." -ForegroundColor Cyan

		Write-Host

		$currentJsonResultFile = $currentJsonResultFile + 1
	} catch
	{
		Write-Error "[!] Failed to extract $result."
		Write-Error $_.Exception.Message
		
		RemoveSharphoundZip
		RemoveSharphoundFolder
		RemoveSharphoundResultsFolder
		
		exit 1
	}
}
Write-Host "[*] Written content of JSON files to console." -ForegroundColor Cyan

# Task 10: Clean Up Extra Files
ShowProgress -Id 0 -ProgressState $ProgressState -Activity "Sharphound Installation and Scan" -CurrentOperation "Cleaning up..."

# Clean up
Write-Host "[*] Cleaning up..." -ForegroundColor Cyan
RemoveSharphoundZip
RemoveSharphoundFolder
RemoveSharphoundResultsFolder
Write-Host "[*] Clean up done." -ForegroundColor Cyan

# Task 11: Complete the progress bar
ShowProgress -Id 0 -ProgressState $ProgressState -Activity "Sharphound Installation and Scan" -Completed

exit 0
