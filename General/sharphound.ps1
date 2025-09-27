<#
	.SYNOPSIS
	Installs and runs the Sharphound data collector.

	.DESCRIPTION
	Installs the Sharphound data collector from a running Bloodhound instance and runs a scan querying all the domain info.

	.PARAMETER BloodhoundIP
	Specifies the IP address of the machine running Bloodhound where the API request for downloading Sharphound will be sent.

	.PARAMETER BloodhoundPort
	Specifies the port number on the machine running Bloodhound where the API request for downloading Sharphound will be sent.

	.PARAMETER TokenKey
	Specifies the Bloodhound API token key used for authenticating on the Bloodhound API.

	.PARAMETER TokenID
	Specifies the Bloodhound API token ID for the TokenKey used.

	.PARAMETER TLS
	Specifies whether the request to the Bloodhound API should be made over 'https://'.

	.EXAMPLE
	PS> .\sharphound.ps1 -BloodhoundIP 10.10.10.5 -BloodhoundPort 8080 -TokenKey LXeVkQGxqCDOG4CXXsiQBPj3In6ACWc5/yyd66IgeBDUqNcZ/rqCaA== -TokenID 1426fdbd-10dc-44ab-a3a4-e28e045412fa

	.EXAMPLE
	PS> .\sharphound.ps1 -BloodhoundIP 10.10.10.5 -BloodhoundPort 8080 -TokenKey LXeVkQGxqCDOG4CXXsiQBPj3In6ACWc5/yyd66IgeBDUqNcZ/rqCaA== -TokenID 1426fdbd-10dc-44ab-a3a4-e28e045412fa -TLS
#>

param(
	[Parameter(Mandatory=$true)]
	[string] $BloodhoundIP,
	[Parameter(Mandatory=$false)]
	[string] $BloodhoundPort,
	[Parameter(Mandatory=$true)]
	[string] $TokenKey,
	[Parameter(Mandatory=$true)]
	[string] $TokenID,
	[Parameter(Mandatory=$false)]
	[switch] $TLS
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
$totalScriptTasks = 6
$currentScriptTask = 1
$tempPath = "$env:TEMP"
$sharphoundZipPath = "$tempPath\sharphound.zip"
$sharphoundPath = "$tempPath\sharphound"
$sharphoundResultsPath = "$tempPath\Sharphound"
$sharphoundExe = "$sharphoundPath\Sharphound.exe"


# Script Start
Write-Progress -Activity "Sharphound Installation and Scan" -CurrentOperation "Checking TLS requirement..." -Id 0 -PercentComplete (($currentScriptTask / $totalScriptTasks) * 100)
$currentScriptTask = $currentScriptTask + 1

if ($TLS)
{
	$BASE_URL = "https://${BloodhoundIP}:${BloodhoundPort}"
} else
{
	$BASE_URL = "http://${BloodhoundIP}:${BloodhoundPort}"
}

$SHARPHOUND_DOWNLOAD_URI = "/api/v2/collectors/sharphound/latest"
$METHOD = "GET"

Write-Progress -Activity "Sharphound Installation and Scan" -CurrentOperation "Building signature..." -Id 0 -PercentComplete (($currentScriptTask / $totalScriptTasks) * 100)
$currentScriptTask = $currentScriptTask + 1

$totalSignatureBuildTasks = 4
$currentSignatureBuildTask = 1

# Calculate the HMAC signature digest required by Bloodhound to accept the request

# Setup HMAC SHA256 Digester
Write-Progress -CurrentOperation "Setting up HMAC SHA256 digester..." -Id 1 -ParentId 0 -PercentComplete (($currentSignatureBuildTask / $totalSignatureBuildTasks) * 100)
$currentSignatureBuildTask = $currentSignatureBuildTask + 1

$digester = New-Object System.Security.Cryptography.HMACSHA256
$tokenKeyBytes = [Text.Encoding]::ASCII.GetBytes($TokenKey)
$digester.Key = $tokenKeyBytes


# Step 1: Compute HMAC for the OperationKey (Method + URI)
Write-Progress -CurrentOperation "Generating OperationKey HMAC digest..." -Id 1 -ParentId 0 -PercentComplete (($currentSignatureBuildTask / $totalSignatureBuildTasks) * 100)
$currentSignatureBuildTask = $currentSignatureBuildTask + 1

$operationKey = "$METHOD$SHARPHOUND_DOWNLOAD_URI"
$operationKeyBytes = [Text.Encoding]::ASCII.GetBytes($operationKey)
$operationKeyDigest = $digester.ComputeHash($operationKeyBytes)


# Step 2: Compute HMAC for the DateKey (RFC3339)
Write-Progress -CurrentOperation "Generating DateKey HMAC digest..." -Id 1 -ParentId 0 -PercentComplete (($currentSignatureBuildTask / $totalSignatureBuildTasks) * 100)
$currentSignatureBuildTask = $currentSignatureBuildTask + 1

$digester.Key = $operationKeyDigest
$datetime = (Get-Date).ToString("yyyy-MM-dd'T'HH:mm:ss.fffffffzzz")
$datetimeBytes = [Text.Encoding]::ASCII.GetBytes($datetime.Substring(0,13))
$datetimeDigest = $digester.ComputeHash($datetimeBytes)

# Step 3: Encode signature in Base64
Write-Progress -CurrentOperation "Generating final HMAC digest..." -Id 1 -ParentId 0 -PercentComplete (($currentSignatureBuildTask / $totalSignatureBuildTasks) * 100)
$currentSignatureBuildTask = $currentSignatureBuildTask + 1

$digester.Key = $datetimeDigest
$emptyString = ""
$emptyStringBytes = [Text.Encoding]::ASCII.GetBytes($emptyString)
$finalDigest = $digester.ComputeHash($emptyStringBytes)

Write-Progress -Id 1 -ParentId 0 -Completed

Write-Progress -Activity "Sharphound Installation and Scan" -CurrentOperation "Base64 encoding final HMAC digest..." -Id 0 -PercentComplete (($currentScriptTask / $totalScriptTasks) * 100)
$currentScriptTask = $currentScriptTask + 1

# Encode the final digest to Base64
$base64Signature = [Convert]::ToBase64String($finalDigest)


$HEADERS = @{
	"Accept" = "Application/octet-stream"
	"Prefer" = "0"
	"Authorization" = "bhesignature $TokenID"
	"RequestDate" = $datetime
	"Signature" = $base64Signature
	"Content-Type" = "application/json"
}

$FINAL_URL = "$BASE_URL$SHARPHOUND_DOWNLOAD_URI"

# Disable Windows Virtus and Threat Protection
Write-Warning "[*] Installing/Running Sharphound requires Windows Protection to be disabled temporarily..."

# Original values
$realtimeMonitoringOriginal = (Get-MpPreference).DisableRealtimeMonitoring
$mapsReportingOriginal = (Get-MpPreference).MAPSReporting
$submitSamplesConsentOriginal = (Get-MpPreference).SubmitSamplesConsent

ManageWindowsProtection -Disable

# Downloading Sharphound archive from Bloodhound API
try
{
	Write-Progress -Activity "Sharphound Installation and Scan" -CurrentOperation "Downloading Sharphound archive from Bloodhound API..." -Id 0 -PercentComplete (($currentScriptTask / $totalScriptTasks) * 100)
	$currentScriptTask = $currentScriptTask + 1

	Write-Host "[*] Downloading Sharphound..." -ForegroundColor Cyan

	Invoke-WebRequest -Uri $FINAL_URL -Method $METHOD -Headers $HEADERS -Outfile $sharphoundZipPath -ErrorAction Stop

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

# Sharphound scan
try
{
	Write-Progress -Activity "Sharphound Installation and Scan" -CurrentOperation "Running Sharphound scan..." -Id 0 -PercentComplete (($currentScriptTask / $totalScriptTasks) * 100)
	$currentScriptTask = $currentScriptTask + 1

	Write-Host "[*] Running Sharphound..." -ForegroundColor Cyan
	
	Write-Host "[*] Creating Sharphound results directory $sharphoundResultsPath..." -ForegroundColor Cyan
	New-Item -Path $sharphoundResultsPath -ItemType Directory -Force
	Write-Host "[*] Created Sharphound results directory $sharphoundResultsPath." -ForegroundColor Cyan

	Start-Process -Wait -FilePath $sharphoundExe -ArgumentList "-c All --OutputDirectory $sharphoundResultsPath" -ErrorAction Stop
	
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

# Reset Windows Protection
ManageWindowsProtection -Reset

# Clean up
CleanUp

# Complete the progress bar
Write-Progress -Activity "Sharphound Installation and Scan" -Id 0 -Completed

exit 0
