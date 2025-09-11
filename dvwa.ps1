# Install choco package manager
Write-Host "Installing choco..." -ForegroundColor Cyan
IEX((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install PHP
# Create PHP install directory
$phpPath = "C:\tools\php84"

if (-not (Test-Path $phpPath))
{
	Write-Host "[*] Installing PHP 8.4.11 under $phpPath..." -ForegroundColor Cyan
	choco install php --version=8.4.11 --package-parameters="/InstallDir:$phpPath" -y --ignore-checksums
	
	if (-not (Test-Path $phpPath))
	{
		Write-Error "[-] Failed to install PHP."
		exit 1
	}
	
	Write-Host "[*] PHP 8.4.11 installed and added to PATH environment variable." -ForegroundColor Cyan
} else
{
	Write-Host "[*] $phpPath already exists. Skipping installation..." -ForegroundColor Cyan
	Write-Host "[*] If you think this is a mistake, delete $phpPath and try again." -ForegroundColor Cyan
}

# Setup IIS to support PHP with FastCGI
# Check if php-cgi.exe exists
$phpCgiPath = "$phpPath\php-cgi.exe"
if (-not (Test-Path $phpCgiPath))
{
	Write-Error "[-] $phpCgiPath not found. Check your PHP installation."
	exit 1
}

# Install MySQL
$mysqlPath = "C:\tools\mysql"
$mysqlService = "MySQL"

if (-not (Test-Path $mysqlPath))
{
	Write-Host "[*] Installing MySQL 9.2.0 into $mysqlPath..." -ForegroundColor Cyan
	choco install mysql --version=9.1.0 -y --ignore-checksums
	
	if (-not (Test-Path $mysqlPath))
	{
		Write-Error "[-] Failed to install MySQL."
		exit 1
	}
	
	Write-Host "[*] MySQL 9.2.0 installed." -ForegroundColor Cyan
} else
{
	Write-Host "[*] $mysqlPath already exists. Skipping installation..." -ForegroundColor Cyan
	Write-Host "[*] If you think this is a mistake, delete $mysqlPath and try again." -ForegroundColor Cyan
}

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

$dvwaSitePath = "C:\inetpub\wwwroot\dvwa"
if ((Test-Path $dvwaSitePath))
{
	Remove-Item -Path $dvwaSitePath -Recurse -Force
}

Copy-Item $dvwaSrc $dvwaSitePath -Recurse -Force

$webAdministrationModuleAvailable = Get-Module -ListAvailable -Name WebAdministration
if (-not $webAdministrationModuleAvailable)
{
	Write-Error "[!] WebAdministration module not available. Please install it and try again."
	exit 1
}

Import-Module WebAdministration

# Stop IIS Default Web Site
Stop-Website "Default Web Site"
Remove-Item "IIS:\Sites\Default Web Site" -Recurse

# Create new IIS Site called DVWA
New-Item "IIS:\Sites\DVWA" -bindings @{protocol="http";bindingInformation="*:80:"} -physicalPath "C:\inetpub\wwwroot\dvwa" -Force

# Wait until DVWA website starts
do {
	$state = (Get-Website -Name "DVWA").State
	Start-Sleep -Seconds 1
} while ($state -ne "Started")

# Start 'DVWA' site if not started
Start-Website "DVWA"

# Add Application under "SERVER_NAME" > "FastCGI Settings" > "Add Application..." in IIS Manager
Add-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/fastCgi" -Name "." -Value @{ fullPath="$phpCgiPath"; arguments="" } -Force

Get-Website -Name "Default Web Site" | Select-Object Name, State
Get-Website -Name "DVWA" | Select-Object Name, State

# Add Module Mapping under "SERVER_NAME" > "Sites" > "Default Web Site" > "Handler Mappings" > "Add Module Mapping..." in IIS Manager
New-WebHandler -Name "PHP" -Path "*.php" -Verb "*" -Modules "FastCgiModule" -ResourceType "File" -ScriptProcessor $phpCgiPath -PSPath "IIS:\Sites\DVWA" -Force

# Add "index.php" as Default Document under "SERVER_NAME" > "Default Document" > "Add..." in IIS Manager
Add-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/defaultDocument/files" -Name "." -Value @{ value="index.php" } -Force

# Update DVWA config
$dvwaPhpConfig = "$dvwaSitePath\config\config.inc.php"
Copy-Item "$dvwaPhpConfig.dist" $dvwaPhpConfig -Force

if (-not (Test-Path $dvwaPhpConfig))
{
	Write-Error "[!] Error creating $dvwaPhpConfig."
	exit 1
}

# Add MySQL extensions to php.ini
$phpIni = "$phpPath\php.ini"
Add-Content -Path $phpIni -Value @(
	"extension=mysqli"
	"extension=pdo_mysql"
)

Write-Host "[*] PHP set up completed." -ForegroundColor Cyan

# Reset IIS
Write-Host "[*] Resetting IIS..." -ForegroundColor Cyan
iisreset

# Change permissions for IIS_IUSRS user (add write permissions)
$folders = @(
	"C:\inetpub\wwwroot\dvwa\config",
	"C:\inetpub\wwwroot\dvwa\hackable\uploads"
)

foreach ($folder in $folders)
{
	icacls $folder /grant "IIS_IUSRS:(OI)(CI)F" /T
}

# Create MySQL database for DVWA
Write-Host "[*] Creating MySQL database 'dvwa'..." -ForegroundColor Cyan

$mysqlUser = "root"
$mysqlPassword = ""
$mysqlexe = "$mysqlPath\current\bin\mysql.exe"

$sql = @"
CREATE DATABASE IF NOT EXISTS dvwa;
CREATE USER IF NOT EXISTS 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
FLUSH PRIVILEGES;
"@

$sql | & $mysqlExe -u $mySqlUser --password=$mySqlPassword

# Send Request to '/setup.php' to finish DVWA setup.
$setupUrl = "http://localhost/setup.php"

# Create WebSession
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

$setupPage = Invoke-WebRequest -Uri $setupUrl -WebSession $session -UseBasicParsing

$userToken = ($setupPage.InputFields | Where-Object { $_.name -eq "user_token" } | Select-Object -First 1).value

if ($null -eq $userToken)
{
	Write-Error "[!] Failed to get 'user_token' from '/setup.php'."
	exit 1
}

# Form data
$formData = @{
	create_db  = "Create / Reset Database"
	user_token = $userToken
}

# Submit POST request to '/setup.php'
$response = Invoke-WebRequest -Uri $setupUrl -Method POST -Body $formData -WebSession $session -UseBasicParsing

Write-Host "[*] Finished setting up DVWA." -ForegroundColor Cyan

Write-Host "[+] DVWA is ready! Browse to http://localhost/" -ForegroundColor Green
Write-Host "[+] DVWA credentials: admin / password" -ForegroundColor Green
