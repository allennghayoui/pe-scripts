












param(
	[Parameter(Mandatory=$false)]
	[string]$DvwaUser,
	[Parameter(Mandatory=$false)]
	[string]$DvwaPassword
)

# Install PHP
# Create PHP install directory
$phpPath = "C:\tools\php84"

if (-not (Test-Path $phpPath))
{
	Write-Host "[*] Installing PHP 8.4.11 under $phpPath..." -ForegroundColor Cyan
	choco install php --version=8.4.11 -y
}

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
Remove-WebHandler -Name "PHP_via_FastCGI" -ErrorAction SilentlyContinue
New-WebHandler -Path "*.php" -Verb "*" -Modules "FastCgiModule" -ScriptProcessor $phpCgiPath -Name "PHP_via_FastCGI"

$phpIni = "$phpPath\php.ini"
if (-not (Test-Path $phpIni))
{
	Copy-Item "$phpPath\php.ini-production" $phpIni -Force
}

# Configure php.ini
$iniContent = Get-Content $phpIni
$iniContent = $iniContent -replace '^(;?cgi\.fix_pathinfo\s*=).*', 'cgi_fix_path_info = 1'
$iniContent = $iniContent -replace '^(;?display_errors\s*=).*', 'display_errors = On'
$iniContent = $iniContent -replace '^(;?allow_url_include\s*=).*', 'allow_url_include = On'
$iniContent = $iniContent -replace '^(;?extension=mysqli\s*=).*', 'extension=mysqli'
$iniContent = $iniContent -replace '^(;?max_execution_time\s*=).*', 'max_execution_time = 30'
$iniContent | Set-Content $phpIni -Force

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

if ($DvwaUser -and $DvwaPassword)
{
	(Get-Content "$confFile.dist") `
		-replace "getenv('DB_USER') ?: 'dvwa'", "getenv('DB_USER') ?: '$DvwaUser'" `
		-replace "getenv('DB_PASSWORD') ?: 'dvwa'", "getenv('DB_PASSWORD') ?: '$DvwaPassword'" | Set-Content $confFile
}

# Restarting IIS
Write-Host "Restarting IIS..." -ForegroundColor Cyan
iisreset

Write-Host "DVWA is ready! Browse to http://localhost/" -ForegroundColor Green
Write-Host "DVWA credentials: $DvwaUser / $DvwaPassword" -ForegroundColor Green
