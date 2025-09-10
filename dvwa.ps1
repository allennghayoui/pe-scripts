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

# Check if WebAdministration module is available
if (-not (Get-Module -ListAvailable -Name WebAdministration))
{
	Write-Error "[-] WebAdministration module not found."
	exit 1
}

Import-Module WebAdministration
#Remove-WebHandler -Name "PHP_via_FastCGI" -ErrorAction SilentlyContinue
#New-WebHandler -Path "*.php" -Verb "*" -Modules "FastCgiModule" -ScriptProcessor $phpCgiPath -Name "PHP_via_FastCGI"
Add-Webconfiguration 'system.webserver/fastcgi' -value @{ 'fullPath' = $phpCgiPath }

$phpIni = "$phpPath\php.ini"
if (-not (Test-Path $phpIni))
{
	Copy-Item "$phpPath\php.ini-production" $phpIni -Force
}

# Configure php.ini
Write-Output "extension=mysqli" >> $phpIni
Write-Output "extension=pdo_mysql" >> $phpIni

Write-Host "[*] PHP set up completed." -ForegroundColor Cyan

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
Add-WebConfigurationProperty -pspath "IIS:\Sites\Default Web Site" -filter "system.webServer/defaultDocument/files" -name "." -value @{value="index.php"}

# Creating MySQL Database for DVWA
Write-Host "Creating DVWA database..." -ForegroundColor Cyan

$mysqlUser = "root"
$mysqlPassword = ""
$mysqlexe = "$mysqlPath\current\bin\mysql.exe"

$sql = @"
CREATE DATABASE dvwa;
CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'dvwa';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
FLUSH PRIVILEGES;
"@

$sql | & $mysqlexe -u $mysqlUser --password=$mysqlPassword

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

# Call setup.php to finish setting up DVWA
# URL to setup.php
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
Invoke-WebRequest -Uri $setupUrl -Method POST -Body $formData -UseBasicParsing

Write-Host "[*] Finished setting up DVWA." -ForegroundColor Cyan

# Restarting IIS
Write-Host "[*] Restarting IIS..." -ForegroundColor Cyan
iisreset

Write-Host "[+] DVWA is ready! Browse to http://localhost/" -ForegroundColor Green
Write-Host "[+] DVWA credentials: admin / password" -ForegroundColor Green
