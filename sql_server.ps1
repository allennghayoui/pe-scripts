# 1. SQL Server is paid only Express edition is free
# https://www.microsoft.com/en/sql-server/sql-server-downloads
# Difference between editions is in the limit max 10GB DBs 1GB of memory
# and 1 processors. No agent for task automation, backup compression,
# log shipping, and advanced business intelligence tools.
#
# SQL Server Express 2022 download link
# https://go.microsoft.com/fwlink/p/?linkid=2216019&culture=en-us

############################################################################

$tempPath = "$env:TEMP"

# Download SQL Server Installer
$sqlServerSetupPath = "$tempPath\sqlserver.exe"

Write-Host "Downloading SQL Server Installer into $sqlServerSetupPath..." -ForegroundColor Cyan
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?linkid=2216019&culture=en-us" -OutFile $sqlServerSetupPath -UseBasicParsing

Write-Host "Installing MSSQL..." -ForegroundColor Cyan
# Questions
# 1. Should the user specify the SQLSVCACCOUNT and password + SQL Admins group?
& "$sqlServerSetupPath" /Quite /IAcceptSqlServerLicenseTerms /Action=Install `
	/InstallPath="C:\Program Files\Microsoft SQL Server" `
	/INSTANCENAME=MSSQLSERVER `
	/SQLSVCACCOUNT="MYDOMAIN\sql_svc" /SQLSVCPASSWORD="P@ssw0rd" /SQLSVCSTARTUPTYPE="Automatic" `
	/SQLSYSADMINACCOUNTS="MYDOMAIN\SQL Admins" `
	/TCPENABLED=1

Write-Host "Removing $sqlServerSetupPath..." -ForegroundColor Cyan
Remove-Item -Path $sqlServerSetupPath -Force
