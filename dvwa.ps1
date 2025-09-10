# Install choco package manager
Write-Host "Installing choco..." -ForegroundColor Cyan
IEX((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install PHP
# Create PHP install directory
$phpPath = "C:\tools\php"

if (-not (Test-Path $phpPath))
{
	Write-Host "[*] Installing PHP 8.4.11 under $phpPath..." -ForegroundColor Cyan
	choco install php --version=8.4.11 -y
}

Rename-Item -Path "C:\tools\php84" -NewName "php"

if (-not (Test-Path $phpPath))
{
	Write-Error "[-] Failed to install PHP."
	exit 1
}

Write-Host "[*] PHP 8.4.11 installed." -ForegroundColor Cyan

# Setup IIS to support PHP with FastCGI
# Check if php-cgi.exe exists
$phpCgiPath = "$phpPath\php-cgi.exe"
if (-not (Test-Path $phpCgiPath))
{
	Write-Error "[-] php-cgi.exe not found."
	exit 1
}



$phpIni = "$phpPath\php.ini"
if (-not (Test-Path $phpIni))
{
	Copy-Item "$phpPath\php.ini-production" $phpIni -Force
}

# Configure php.ini
Add-Content -Path $phpIni -Value @(
    "extension=mysqli"
    "extension=pdo_mysql"
)

Write-Host "[*] PHP set up completed." -ForegroundColor Cyan

# Reset IIS
Write-Host "[*] Resetting IIS..." -ForegroundColor Cyan
iisreset

# Install MySQL
$mysqlPath = "C:\tools\mysql"
$mysqlService = "MySQL"

if (-not (Test-Path $mysqlPath))
{
	Write-Host "[*] Installing MySQL 9.2.0 into $mysqlPath..." -ForegroundColor Cyan
	choco install mysql --version=9.2.0 -y
}

if (-not (Test-Path $mysqlPath))
{
	Write-Error "[-] Failed to install MySQL."
	exit 1
}

Write-Host "[*] MySQL installed." -ForegroundColor Cyan

$mysqlServiceStatus = (Get-Service -Name $mysqlService).Status

if (-not $mysqlServiceStatus -eq "Running")
{
	Write-Host "[*] Starting MySQL service..." -ForegroundColor Cyan
	Start-Service $mysqlService
}

# Download and configure DVWA with IIS
Write-Host "Setting up DVWA..." -ForegroundColor Cyan

$dvwaZip = "$env:TEMP\dvwa.zip"

Invoke-WebRequest -Uri "https://github.com/digininja/DVWA/archive/master.zip" -OutFile $dvwaZip

# Extract files from dvwa.zip
Expand-Archive -Path $dvwaZip -DestinationPath $env:TEMP -Force
$dvwaSrc = "$env:TEMP\DVWA-master"

$sitePath = "C:\inetpub\wwwroot\dvwa"
if ((Test-Path $sitePath))
{
	Remove-Item -Path $sitePath -Recurse -Force
}

Copy-Item $dvwaSrc $sitePath -Recurse -Force

# Point IIS Default Web Site to DVWA root
Set-ItemProperty "IIS:\Sites\Default Web Site" -Name physicalPath -Value $sitePath
# Check if WebAdministration module is available
if (-not (Get-Module -ListAvailable -Name WebAdministration))
{
	Write-Error "[-] WebAdministration module not found."
	exit 1
}

Import-Module WebAdministration
Start-Sleep -Seconds 5
# Add PHP FastCGI handler
Add-WebConfigurationProperty -pspath "IIS:\Sites\Default Web Site" `
  -filter "system.webServer/handlers" -name "." `
  -value @{name="PHP_via_FastCGI"; path="*.php"; verb="*"; modules="FastCgiModule"; scriptProcessor=$phpCgiPath; resourceType="Either"}

# Register PHP in FastCGI
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
  -filter "system.webServer/fastCgi" -name "." `
  -value @{ fullPath = $phpCgiPath }

# Add index.php as default document
Add-WebConfigurationProperty -pspath "IIS:\Sites\Default Web Site" `
  -filter "system.webServer/defaultDocument/files" -name "." `
  -value @{value="index.php"}

# Creating MySQL Database for DVWA
Write-Host "Creating DVWA database..." -ForegroundColor Cyan

$mysqlUser = "root"
$mysqlPassword = ""
$mysqlexe = "$mysqlPath\current\bin\mysql.exe"

$sql = @"
CREATE DATABASE IF NOT EXISTS dvwa;
CREATE USER IF NOT EXISTS 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';
CREATE USER IF NOT EXISTS 'dvwa'@'127.0.0.1' IDENTIFIED BY 'p@ssw0rd';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'127.0.0.1';
FLUSH PRIVILEGES;
"@

$sql | & $mysqlExe -u $rootUser --password=$rootPass

# Update DVWA config
$confFile = "$sitePath\config\config.inc.php"

(Get-Content "C:\inetpub\wwwroot\dvwa\config\config.inc.php.dist") | Set-Content $confFile

# Change permissions for IIS_IUSRS user (add write permissions)
$folders = @(
	"C:\inetpub\wwwroot\dvwa\config",
	"C:\inetpub\wwwroot\dvwa\hackable\uploads"
)

foreach ($folder in $folders)
{
	icacls $folder /grant "IIS_IUSRS:(OI)(CI)F" /T
}

iisreset

# Call setup.php to finish setting up DVWA
$setupUrl = "http://localhost/setup.php"

# Get the page to extract the user_token
$page = Invoke-WebRequest -Uri $setupUrl -UseBasicParsing

# Find the hidden input named 'user_token' from InputFields
$userTokenField = $page.InputFields | Where-Object { $_.name -eq "user_token" } | Select-Object -First 1

if ($userTokenField)
{
	$userToken = $userTokenField.value
} else
{
	throw "Could not find user_token in InputFields"
}

# Form data
$formData = @{
	create_db  = "Create / Reset Database"
	user_token = $userToken
}

# Submit POST request
$response = Invoke-WebRequest -Uri $setupUrl -Method POST -Body $formData -UseBasicParsing

Write-Host $response.Content

Write-Host "[*] Finished setting up DVWA." -ForegroundColor Cyan
Write-Host "[+] DVWA is ready! Browse to http://localhost/" -ForegroundColor Green
Write-Host "[+] DVWA credentials: admin / password" -ForegroundColor Green
