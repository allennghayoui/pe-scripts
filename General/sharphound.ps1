param(
	[Parameter(Mandatory=$true)]
	[string] $BloodhoundIP,
	[Parameter(Mandatory=$false)]
	[string] $BloodhoundPort,
	[Parameter(Mandatory=$true)]
	[string] $TokenID,
	[Parameter(Mandatory=$true)]
	[string] $TokenKey,
	[Parameter(Mandatory=$false)]
	[switch] $TLS
)

$tempPath = "$env:TEMP"
$sharphoundZipPath = "$tempPath\sharphound.zip"
$sharphoundPath = "$tempPath\sharphound"
$sharphoundExe = "$sharphoundPath\Sharphound.exe"

if ($TLS)
{
	$BASE_URL = "https://${BloodhoundIP}:${BloodhoundPort}"
} else
{
	$BASE_URL = "http://${BloodhoundIP}:${BloodhoundPort}"
}

$SHARPHOUND_DOWNLOAD_URI = "/api/v2/collectors/sharphound/latest"
$METHOD = "GET"

# Calculate the HMAC signature digest required by Bloodhound to accept the request
# Setup HMAC SHA256 Digester
$digester = New-Object System.Security.Cryptography.HMACSHA256
$tokenKeyBytes = [Text.Encoding]::ASCII.GetBytes($TokenKey)
$digester.Key = $tokenKeyBytes

# Step 1: Compute HMAC for the OperationKey (Method + URI)
$operationKey = "$METHOD$SHARPHOUND_DOWNLOAD_URI"
$operationKeyBytes = [Text.Encoding]::ASCII.GetBytes($operationKey)
$operationKeyDigest = $digester.ComputeHash($operationKeyBytes)

# Step 2: Compute HMAC for the DateKey (RFC3339)
$digester.Key = $operationKeyDigest
$datetime = (Get-Date).ToString("yyyy-MM-dd'T'HH:mm:ss.fffffffzzz")
$datetimeBytes = [Text.Encoding]::ASCII.GetBytes($datetime.Substring(0,13))
$datetimeDigest = $digester.ComputeHash($datetimeBytes)

# Step 3: Encode signature in Base64
$digester.Key = $datetimeDigest
$emptyString = ""
$emptyStringBytes = [Text.Encoding]::ASCII.GetBytes($emptyString)
$finalDigest = $digester.ComputeHash($emptyStringBytes)

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

exit 0
