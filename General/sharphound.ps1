

# WARNING: Some files downloaded through this script might be blocked by Windows AV.

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

$totalScriptTasks = 6
$currentScriptTask = 1
$tempPath = "$env:TEMP"
$sharphoundZipPath = "$tempPath\sharphound.zip"
$sharphoundPath = "$tempPath\sharphound"
$sharphoundExe = "$sharphoundPath\Sharphound.exe"


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
	exit 1
}

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
	exit 1
}

try
{
	Write-Progress -Activity "Sharphound Installation and Scan" -CurrentOperation "Running Sharphound scan..." -Id 0 -PercentComplete (($currentScriptTask / $totalScriptTasks) * 100)
	$currentScriptTask = $currentScriptTask + 1

	Write-Host "[*] Running Sharphound..." -ForegroundColor Cyan

	Start-Process -Wait -FilePath $sharphoundExe -ArgumentList "-c All --OutputDirectory $sharphoundPath" -ErrorAction Stop
	$createdZipFiles = (Get-ChildItem -Path $sharphoundPath -Filter "*_Bloodhound.zip").Name -join ", "

	Write-Host "[*] Sharphound done. The results are contained in the following zip files: $createdZipFiles" -ForegroundColor Cyan
} catch
{
	Write-Error "[!] Error running Sharphound."
	Write-Error $_.Exception.Message
	exit 1
}


Write-Progress -Activity "Sharphound Installation and Scan" -Id 0 -Completed

exit 0
