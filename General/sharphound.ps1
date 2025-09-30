<#
	.SYNOPSIS
	Installs and runs the Sharphound data collector.

	.DESCRIPTION
	Installs the Sharphound data collector from a running Bloodhound instance and runs a scan querying all the domain info and uploads the results to an Amazon S3 Bucket.

	.PARAMETER S3PresignedURL
	Specifies the presigned URL for the S3 bucket which the Sharphound scan results will be uploaded to.

	.EXAMPLE
	PS> .\sharphound.ps1 -S3PresignedURL 
#>

param(
	[Parameter(Mandatory=$true)]
	[string] $S3PresignedURL
)


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

# Function declarations
function RemoveSharphoundZip
{
	if ((Test-Path -Path $sharphoundZipPath))
	{
		try
		{
			Write-Host "[*] Deleting $sharphoundZipPath..." -ForegroundColor Cyan
			Remove-Item -Path $sharphoundZipPath -Force
			Write-Host "[*] Deleted $sharphoundZipPath." -ForegroundColor Cyan
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
			Write-Host "[*] Deleting $sharphoundPath..." -ForegroundColor Cyan
			Remove-Item -Path $sharphoundPath -Force -Recurse
			Write-Host "[*] Deleted $sharphoundPath." -ForegroundColor Cyan
		} catch
		{
			Write-Error $_.Exception.Message
			exit 1
		}
	}
}

function CleanUp
{
	RemoveSharphoundZip
	RemoveSharphoundFolder
}

function CalculateProgressPercentage
{
	$percentage = ($currentTask / $totalTasks) * 100
	return [math]::Round($percentage, 2)
}


# Variables
# Progress
$totalTasks = 6
$currentTask = 1

# Paths
$tempPath = "$env:TEMP"
$sharphoundZipPath = "$tempPath\sharphound.zip"
$sharphoundPath = "$tempPath\sharphound"
$sharphoundResultsPath = "$tempPath\SharphoundResults"
$sharphoundExePath = "$sharphoundPath\Sharphound.exe"

# Disable Windows Virtus and Threat Protection
Write-Warning "[*] Downloading/Running Sharphound requires Windows Protection to be disabled temporarily..."

Write-Progress -Activity "Sharphound Installation and Scan" -CurrentOperation "Disabling Windows Protection temporarily..." -Id 0 -PercentComplete (CalculateProgressPercentage)
$currentScriptTask = $currentScriptTask + 1

# Original values
$realtimeMonitoringOriginal = (Get-MpPreference).DisableRealtimeMonitoring
$mapsReportingOriginal = (Get-MpPreference).MAPSReporting
$submitSamplesConsentOriginal = (Get-MpPreference).SubmitSamplesConsent

ManageWindowsProtection -Disable

Write-Host "<PROGRESS>(CalculateProgressPercentage)%</PROGRESS>"
Write-Progress -Activity "Sharphound Installation and Scan" -CurrentOperation "Downloading the Sharphound archive..." -Id 0 -PercentComplete (CalculateProgressPercentage)
$currentTask = $currentTask + 1

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

# Extracting downloaded Sharphound archive
try
{
	Write-Host "<PROGRESS>(CalculateProgressPercentage)%</PROGRESS>"
	Write-Progress -Activity "Sharphound Installation and Scan" -CurrentOperation "Extracting Sharphound archive..." -Id 0 -PercentComplete (CalculateProgressPercentage)
	$currentTask = $currentTask + 1

	Write-Host "[*] Extracting $sharphoundZipPath..." -ForegroundColor Cyan

	Expand-Archive -Path $sharphoundZipPath $sharphoundPath -ErrorAction Stop

	Write-Host "[*] Extracted $sharphoundZipPath into $sharphoundPath." -ForegroundColor Cyan
} catch
{
	Write-Error "[!] Error extrating $sharphoundZipPath"
	Write-Error $_.Exception.Message
	
	RemoveSharphoundZip
	
	ManageWindowsProtection -Reset
	
	exit 1
}

# Create directory for Sharphound results
Write-Host "<PROGRESS>(CalculateProgressPercentage)%</PROGRESS>"
Write-Progress -Activity "Sharphound Installation and Scan" -CurrentOperation "Creating directory for Sharphound results..." -Id 0 -PercentComplete (CalculateProgressPercentage)
$currentTask = $currentTask + 1

try
{
	Write-Host "[*] Creating Sharphound results directory $sharphoundResultsPath..." -ForegroundColor Cyan
	New-Item -Path $sharphoundResultsPath -ItemType Directory -Force -ErrorAction Stop
	Write-Host "[*] Created Sharphound results directory $sharphoundResultsPath." -ForegroundColor Cyan
} catch
{
	Write-Error "[!] Failed to create directory: '$sharphoundResultsPath'."
	Write-Error $_.Exception.Message
	
	RemoveSharphoundZip
	
	exit 1
}

# Run Sharphound scan
Write-Host "<PROGRESS>(CalculateProgressPercentage)%</PROGRESS>"
Write-Progress -Activity "Sharphound Installation and Scan" -CurrentOperation "Running Sharphound scan..." -Id 0 -PercentComplete (CalculateProgressPercentage)
$currentTask = $currentTask + 1

try
{
	Write-Host "[*] Running Sharphound..." -ForegroundColor Cyan
	Start-Process -Wait -FilePath $sharphoundExePath -ArgumentList "-c All --OutputDirectory $sharphoundResultsPath" -ErrorAction Stop
	$resultZipFiles = (Get-ChildItem -Path $sharphoundResultsPath -Filter "*_Bloodhound.zip").Name -join ", "
	Write-Host "[*] Sharphound scan is done. The results are contained in the following zip files: $resultZipFiles" -ForegroundColor Cyan
} catch
{
	Write-Error "[!] Error running Sharphound."
	Write-Error $_.Exception.Message
	
	RemoveSharphoundZip
	RemoveSharphoundFolder
	
	ManageWindowsProtection -Reset
	
	exit 1
}

Write-Host "<PROGRESS>(CalculateProgressPercentage)%</PROGRESS>"
Write-Progress -Activity "Sharphound Installation and Scan" -CurrentOperation "Resetting Windows Protection..." -Id 0 -PercentComplete (CalculateProgressPercentage)
$currentTask = $currentTask + 1

# Reset Windows Protection
ManageWindowsProtection -Reset

# Upload Sharphound scan results to S3 Bucket
Write-Host "<PROGRESS>(CalculateProgressPercentage)%</PROGRESS>"
Write-Progress -Activity "Sharphound Installation and Scan" -CurrentOperation "Uploading Sharphound results to Amazon S3..." -Id 0 -PercentComplete (CalculateProgressPercentage)
$currentTask = $currentTask + 1

foreach ($result in $resultZipFiles)
{
	try
	{
		Write-Host "[*] Uploading '$result' to S3 bucket..." -ForegroundColor Cyan
		Invoke-WebRequest -Uri $S3PresignedURL -Method PUT -InFile $result -ContentType "text/plain"
		Write-Host "[*] Uploaded '$result' to S3 bucket" -ForegroundColor Cyan
	} catch
	{
		Write-Error "[!] Failed to upload file: '$result'."
		Write-Error $_.Exception.Message
		exit 1
	}
}

# Clean up
CleanUp

# Complete the progress bar
Write-Progress -Activity "Sharphound Installation and Scan" -Id 0 -Completed

exit 0
