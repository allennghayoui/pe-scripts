<#
	.SYNOPSIS
	Sets up DVWA as a vulnerable web application with IIS.
	
	.DESCRIPTION
	Sets up DVWA as a vulnerable web appliation with IIS by installing PHP and MySQL Server.
	
	.EXAMPLE
	PS> .\dvwa.ps1
#>

######################################## Function Declarations ########################################

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
	CurrentTask  = 1
	TotalTasks   = 26
}

# Paths
$tempDir = "$env:TEMP"
$phpZip = "$tempDir\php.zip"
$vcRedistExe = "$tempDir\VC_redist.x64.exe"
$phpPath = "C:\PHP"
$phpCgiPath = "$phpPath\php-cgi.exe"

if (-not (Test-Path $phpPath))
{
	try
	{
		ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Downloading VC_redist.x64.exe..."
		
		# Install PHP pre-requisite VC_redist.x64.exe
		Write-Host "[*] Downloading VC_redist.x64.exe..." -ForegroundColor Cyan

		Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/VC_redist.x64.exe" -OutFile $vcRedistExe -UseBasicParsing

		Write-Host "[*] Downloaded VC_redist.x64.exe." -ForegroundColor Cyan

		ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Installing VC_redist.x64.exe..."

		Write-Host "[*] Installing VC_redist.x64.exe..." -ForegroundColor Cyan

		Start-Process -Wait -NoNewWindow -FilePath $vcRedistExe -ArgumentList "/install", "/quiet", "/norestart"

		Write-Host "[*] Installed VC_redist.x64.exe." -ForegroundColor Cyan
	} catch
	{
		Write-Error "[!] Failed to install VC_redist.x64.exe"
		Write-Error $_.Exception.Message
		exit 1
	}

	try
	{
		ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Creating directory: '$phpPath'..."
	
		New-Item -ItemType Directory -Path $phpPath | Out-Null

		ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Downloading PHP ZIP file.."
		
		# Download PHP zip
		Write-Host "[*] Downloading PHP ZIP file to $phpZip..." -ForegroundColor Cyan

		Invoke-WebRequest -Uri "https://windows.php.net/downloads/releases/archives/php-8.4.12-nts-Win32-vs17-x64.zip" -OutFile $phpZip -UseBasicParsing

		ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Extracting PHP ZIP file..."
		
		# Extract files into C:\PHP
		Write-Host "[*] Extracting PHP ZIP file to $phpPath..." -ForegroundColor Cyan

		Expand-Archive -Path $phpZip -DestinationPath $phpPath -Force
	
		if (-not (Test-Path $phpPath))
		{
			Write-Error "[!] Failed to install PHP."
			exit 1
		}
	
		Write-Host "[*] PHP installed." -ForegroundColor Cyan
	} catch
	{
		Write-Error "[!] Failed to install PHP."
		Write-Error $_.Exception.Message
		exit 1
	}
} else
{
	Write-Warning "[!] $phpPath already exists. Skipping installation..."
	Write-Warning "[!] If you think this is a mistake, delete $phpPath and try again."
}

# Setup IIS to support PHP with FastCGI
# Check if php-cgi.exe exists
if (-not (Test-Path $phpCgiPath))
{
	Write-Error "[-] $phpCgiPath not found. Check your PHP installation."
	exit 1
}

######################################## MySQL Setup ########################################

$mysqlMsiPath = "$tempDir\mysql-installer-community-8.0.43.0.msi"
$mysqlMsiExtractedContent = "C:\Program Files (x86)\MySQL\MySQL Installer for Windows"
$mysqlInstallerPath = "$mysqlMsiExtractedContent\MySQLInstallerConsole.exe"
$mysqlBinPath = "C:\Program Files\MySQL\MySQL Server 8.0\bin"
$mysqlDaemonPath = "$mysqlBinPath\mysqld.exe"
$mysqlExePath = "$mysqlBinPath\mysql.exe"
$mysqlServiceName = "MySQL"

# Download MySQL MSI
if (-not (Test-Path $mysqlInstallerPath))
{
	ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Downloading MySQL MSI..."

	Write-Host "[*] Downloading MySQL MSI..." -ForegroundColor Cyan

	Invoke-WebRequest -Uri "https://cdn.mysql.com//Downloads/MySQLInstaller/mysql-installer-community-8.0.43.0.msi" -OutFile $mysqlMsiPath -UseBasicParsing

	Write-Host "[*] MySQL MSI downloaded." -ForegroundColor Cyan

	ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Extracting MySQL MSI into '$mysqlMsiExtractedContent'..."

	Write-Host "[*] Extracting MySQL MSI into '$mysqlMsiExtractedContent'..." -ForegroundColor Cyan
	Start-Process msiexec.exe -Wait -ArgumentList "/qb /norestart /i `"$mysqlMsiPath`""
	
	if (-not (Test-Path $mysqlInstallerPath))
	{
		Write-Error "[!] Failed to extract MySQL MSI content into '$mysqlMsiExtractedContent'."
		exit 1
	}
	
	Write-Host "[*] MySQL MSI content extracted into $mysqlMsiExtractedContent." -ForegroundColor Cyan
} else
{
	Write-Warning "[!] $mysqlMsiExtractedContent already exists. Skipping download..."
	Write-Warning "[!] If you think this is a mistake, delete $mysqlMsiExtractedContent and try again."
}

if (-not (Test-Path $mysqlBinPath))
{
	# Install MySQL Server using MySQLInstallerConsole.exe
	try
	{
		ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Installing MySQL Server..."

		Write-Host "[*] Installing MySQL Server..." -ForegroundColor Cyan
		
		Start-Process -Wait -NoNewWindow -FilePath $mysqlInstallerPath -ArgumentList "community install --silent --auto-handle-prereqs --setup-type=server"
		
		Write-Host "[*] MySQL Server installed at $mysqlBinPath." -ForegroundColor Cyan
	} catch
	{
		Write-Error "[!] Failed to install MySQL Server."
		Write-Error $_.Exception.Message
		exit 1
	}
}

if (-not (Get-Service $mysqlServiceName -ErrorAction SilentlyContinue))
{
	# Install MySQL Server Windows Service
	try
	{
		ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Installing MySQL Server Windows Service: '$mysqlServiceName'..."

		Write-Host "[*] Installing MySQL Server Windows Service: '$mysqlServiceName'..." -ForegroundColor Cyan

		Start-Process -Wait -NoNewWindow -FilePath $mysqlDaemonPath -ArgumentList "--install"

		Write-Host "[*] Installed MySQL Server Windows Service: '$mysqlServiceName'." -ForegroundColor Cyan
	} catch
	{
		Write-Error "[!] Failed to install MySQL Server Windows Service: '$mysqlServiceName'."
		Write-Error $_.Exception.Message
		exit 1
	}
	
	# Initialize MySQL Server Windows Service
	try
	{
		ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Initializing MySQL Server Windows Service: '$mysqlServiceName'..."

		Write-Host "[*] Initializing MySQL Server Windows Service: '$mysqlServiceName'..." -ForegroundColor Cyan

		Start-Process -Wait -NoNewWindow -FilePath $mysqlDaemonPath -ArgumentList "--initialize-insecure --console"

		Write-Host "[*] Initialized MySQL Server Windows Service: '$mysqlServiceName'." -ForegroundColor Cyan
	} catch
	{
		Write-Error "[!] Failed to initialize MySQL Server Windows Service: '$mysqlServiceName'."
		Write-Error $_.Exception.Message
		exit 1
	}
}

$mysqlServiceStatus = (Get-Service -Name $mysqlServiceName).Status
if ($mysqlServiceStatus -ne "Running")
{
	# Start MySQL Server Windows Service
	try
	{

		Write-Host "[*] Starting MySQL Server Windows Service: '$mysqlServiceName'..." -ForegroundColor Cyan

		Start-Service $mysqlServiceName
		
		$mysqlServiceStatus = (Get-Service -Name $mysqlServiceName).Status
		
		Write-Host "[*] Service '$mysqlServiceName': $mysqlServiceStatus" -ForegroundColor Cyan
		
		Write-Host "[*] Started MySQL Server Windows Service: '$mysqlServiceName'." -ForegroundColor Cyan
	} catch
	{
		Write-Error "[!] Failed to start MySQL Server Windows Service: '$mysqlServiceName'."
		Write-Error $_.Exception.Message
		exit 1
	}
}

######################################## DVWA Setup ########################################

$dvwaZipPath = "$tempDir\dvwa.zip"
$dvwaSrcPath = "$tempDir\DVWA-master"
$dvwaSiteName = "DVWA"
$dvwaSitePath = "C:\inetpub\wwwroot\$dvwaSiteName"
$dvwaPhpConfig = "$dvwaSitePath\config\config.inc.php"

ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Downloading DVWA ZIP file..."

# Download and configure DVWA with IIS
Write-Host "Setting up DVWA..." -ForegroundColor Cyan

try
{
	Invoke-WebRequest -Uri "https://github.com/digininja/DVWA/archive/master.zip" -OutFile $dvwaZipPath -UseBasicParsing
} catch
{
	Write-Error "[!] Failed to download DVWA zip file."
	Write-Error $_.Exception.Message
	exit 1
}

ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Extracting DVWA ZIP file into '$dvwaZipPath'..."

Write-Host "[*] Extracting DVWA ZIP file into '$dvwaZipPath'..." -ForegroundColor Cyan

# Extract files from dvwa.zip
Expand-Archive -Path $dvwaZipPath -DestinationPath $tempDir -Force

Write-Host "[*] Extracted DVWA ZIP file into '$dvwaZipPath'" -ForegroundColor Cyan

ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Creating Directory: '$dvwaSitePath'..."

if ((Test-Path $dvwaSitePath))
{
	try
	{
		Write-Host "[*] Removing Existing Directory: '$dvwaSitePath'..." -ForegroundColor Cyan
		Remove-Item -Path $dvwaSitePath -Recurse -Force -ErrorAction Stop
		Write-Host "[*] Removed Existing Directory: '$dvwaSitePath'." -ForegroundColor Cyan
	} catch
	{
		Write-Error "[!] Failed to remove existing directory: '$dvwaSitePath'."
		Write-Error $_.Exception.Message
		exit 1
	}
}

# try
# {
# 	Write-Host "[*] Creating Directory: '$dvwaSitePath'..." -ForegroundColor Cyan
# 	New-Item -ItemType Directory -Path $dvwaSitePath -Force -ErrorAction Stop
# 	Write-Host "[*] Created Directory: '$dvwaSitePath'." -ForegroundColor Cyan	
# } catch
# {
# 	Write-Error "[!] Failed to create directory: '$dvwaSitePath'."
# 	Write-Error $_.Exception.Message
# 	exit 1
# }

ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Moving DVWA files into '$dvwaSitePath'..."

# Move contents of $tempDir\DVWA-master to C:\inetpub\wwwroot\dvwa
try
{
	Write-Host "[*] Moving '$dvwaSrcPath' to '$dvwaSitePath'..." -ForegroundColor Cyan
	Move-Item -Path "$dvwaSrcPath\*" -Destination $dvwaSitePath -Force -ErrorAction Stop
	Write-Host "[*] Moved '$dvwaSrcPath' to '$dvwaSitePath'." -ForegroundColor Cyan
} catch
{
	Write-Error "[!] Failed to move '$dvwaSrcPath' to '$dvwaSitePath'"
	Write-Error $_.Exception.Message
	exit 1
}

ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Installing Windows Feature: 'Web-Server' with Management Tools..."

# Check for WebAdministration PowerShell module installation
$webAdministrationModuleAvailable = Get-Module -ListAvailable -Name WebAdministration
if (-not $webAdministrationModuleAvailable)
{
	try
	{
		Write-Host "[*] WebAdministration module not available. Installing..."
		Install-WindowsFeature -Name Web-Server -IncludeManagementTools
		Write-Host "[*] WebAdministration module installed." -ForegroundColor Cyan
	} catch
	{
		Write-Error "[!] Failed to install WebAdministration module."
		Write-Error $_.Exception.Message
		exit 1
	}
}

Import-Module WebAdministration

# Stop IIS Default Web Site
ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Stopping IIS website: 'Default Web Site'..."

Write-Host "[*] Stopping IIS website: 'Default Web Site'..." -ForegroundColor Cyan
Stop-Website "Default Web Site"
Write-Host "[*] Stopped IIS website: 'Default Web Site'." -ForegroundColor Cyan

ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Stopping IIS website: 'Default Web Site'..."

Write-Host "[*] Removing IIS website 'Default Web Site'..." -ForegroundColor Cyan
Remove-Item "IIS:\Sites\Default Web Site" -Recurse
Write-Host "[*] Removing IIS website: 'Default Web Site'..." -ForegroundColor Cyan

# Create new IIS Site called DVWA
ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Creating IIS website: '$dvwaSiteName'..."

Write-Host "[*] Creating IIS website: '$dvwaSiteName'..." -ForegroundColor Cyan
New-Item "IIS:\Sites\$dvwaSiteName" -bindings @{protocol="http";bindingInformation="*:80:"} -physicalPath "C:\inetpub\wwwroot\dvwa" -Force
Write-Host "[*] Created IIS website: '$dvwaSiteName'..." -ForegroundColor Cyan

ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Starting IIS website: '$dvwaSiteName'..."

# Wait for website to start
Start-Sleep -Seconds 5

# Get website state
$websiteState = (Get-Website -Name $dvwaSiteName).State

if ($websiteState -ne "Started")
{
	# Start 'DVWA' site if not started
	Start-Website $dvwaSiteName
}

$websiteState = (Get-Website -Name $dvwaSiteName).State
if ($websiteState -ne "Started")
{
	Write-Error "[!] Failed to start website $dvwaSiteName."
	exit 1
}

ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Configuring IIS website: '$dvwaSiteName'..."

# Add Application under "SERVER_NAME" > "FastCGI Settings" > "Add Application..." in IIS Manager
Add-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/fastCgi" -Name "." -Value @{ fullPath="$phpCgiPath"; arguments="" } -Force

Get-Website -Name $dvwaSiteName | Select-Object Name, State

# Add Module Mapping under "SERVER_NAME" > "Sites" > "Default Web Site" > "Handler Mappings" > "Add Module Mapping..." in IIS Manager
New-WebHandler -Name "PHP" -Path "*.php" -Verb "*" -Modules "FastCgiModule" -ResourceType "File" -ScriptProcessor $phpCgiPath -PSPath "IIS:\Sites\$dvwaSiteName" -Force

# Add "index.php" as Default Document under "SERVER_NAME" > "Default Document" > "Add..." in IIS Manager
Add-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/defaultDocument/files" -Name "." -Value @{ value="index.php" } -Force

# Set Anonymous Authentication to use the Application Pool Identity
Set-WebConfigurationProperty -Filter /system.WebServer/security/authentication/AnonymousAuthentication -name userName -value ""

# Update DVWA config
ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Updating DVWA config file..."

Write-Host "[*] Updating DVWA config file..." -ForegroundColor Cyan
Copy-Item "$dvwaPhpConfig.dist" $dvwaPhpConfig -Force
Write-Host "[*] Updated DVWA config file." -ForegroundColor Cyan

if (-not (Test-Path $dvwaPhpConfig))
{
	Write-Error "[!] Error creating $dvwaPhpConfig."
	exit 1
}

# Add MySQL extensions to php.ini
ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Adding extensions to php.ini..."

Write-Host "[*] Adding required extensions to php.ini..." -ForegroundColor Cyan
$phpIni = "$phpPath\php.ini"
Add-Content -Path $phpIni -Value @(
	"extension=mysqli"
	"extension=pdo_mysql"
	"extension=gd"
)
Write-Host "[*] Added required extensions to php.ini." -ForegroundColor Cyan

Write-Host "[*] PHP set up completed." -ForegroundColor Cyan

# Reset IIS
ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Resetting IIS..."

Write-Host "[*] Resetting IIS..." -ForegroundColor Cyan
iisreset
Write-Host "[*] Reset IIS." -ForegroundColor Cyan

# Change permissions for IIS_IUSRS user (add write permissions)
$folders = @(
	"C:\inetpub\wwwroot\dvwa",
	"C:\inetpub\wwwroot\dvwa\config",
	"C:\inetpub\wwwroot\dvwa\hackable\uploads"
)

ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Granting required permissions..." -PercentComplete $progress

$currentFolder = 1
$totalFolders = $folders.Length
foreach ($folder in $folders)
{
	icacls $folder /grant "IIS_IUSRS:(OI)(CI)F" /T | Out-Null
	icacls $folder /grant "IUSR:(OI)(CI)(RX)" /T | Out-Null
}

# Create MySQL database for DVWA
ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Creating MySQL database 'dvwa'..."

Write-Host "[*] Creating MySQL database 'dvwa'..." -ForegroundColor Cyan

$mysqlUser = "root"
$mysqlPassword = ""

$sql = @"
CREATE DATABASE IF NOT EXISTS dvwa;
CREATE USER IF NOT EXISTS 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
FLUSH PRIVILEGES;
"@

$sql | & $mysqlExePath -u $mySqlUser --password=$mySqlPassword

# Send Request to '/setup.php' to finish DVWA setup.
ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -CurrentOperation "Running setup.php script..."

Write-Host "[*] Running setup.php script..." -ForegroundColor Cyan

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

ShowProgress -Id 0 -ProgressState $ProgressState -Activity "DVWA Install and Setup" -Completed

Write-Host "[+] DVWA is ready! Browse to http://localhost/" -ForegroundColor Green
Write-Host "[+] DVWA credentials: 'admin' / 'password'" -ForegroundColor Green

exit 0
