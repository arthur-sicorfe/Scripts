<#	
	.NOTES
	===========================================================================
	 Created on:   	20220104
	 Created by:   	Arthur D
	 Organization: 	Sicorfé Santé
	 Filename:     	ConfigureComputerScript
	===========================================================================
	.DESCRIPTION
	
		ATTENTION :
		
		Activer l'exécution de script PowerShell avant d'éxécuter le script.
		Dans PowerShell en Administrateur : Set-ExecutionPolicy RemoteSigned
		
		Ce script permet en autre de :

		1. Installer des applications
			- Chrome
			- 7-Zip
			- FortiClientVPN
			- TeamViewer
			- Adobe Acrobat Reader
			
		2. Désinstaller McAfee
		
		3. Désactiver OneDrive au démarrage
		
		4. Activer le verrouillage numérique au démarrage
		
		5. Ajouter l'icone du bureau à distance sur le bureau
		
		6. Placer le fond d'écran Sicorfé
		
		7. Renommer l'ordinateur
#>

#Exécution du script en tant qu'administrateur
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

Write-Host "Verify Windget installation..." -ForegroundColor Yellow

# Vérification installation Winget
if (Test-Path ~\AppData\Local\Microsoft\WindowsApps\winget.exe){
    "Winget is already installed `r`n"
}  
else{
    # Installation de Winget
	Write-Host "Can't find Winget. Processing installation." -ForegroundColor Yellow
	Start-Process "ms-appinstaller:?source=https://aka.ms/getwinget"
	$nid = (Get-Process AppInstaller).Id
	Wait-Process -Id $nid
	Write-Host "Winget installed" -ForegroundColor Green
}

##Installation des modules nécessaires
if (Get-Module -ListAvailable -Name PackageManagement)
{
	Write-Host "PackageManagement already installed `r`n"
}
Else
{
	Write-Host "Installing PackageManagement" -ForegroundColor Yellow
	Install-PackageProvider -Name NuGet -Force
	Install-Module -Name PackageManagement -Force
	Write-Host "PackageManagement installed" -ForegroundColor Green
}


Write-Host "Windows 10 Update Tool :"
Write-Host "https://go.microsoft.com/fwlink/?LinkID=799445 `r`n"

do
 {
    ##Menu
	Write-Host [1] - "Install applications"
	Write-Host [2] - "Uninstall McAfee"
	Write-Host [3] - "Disable OneDrive on startup"
	Write-Host [4] - "Enable NumLock keypad on startup"
	Write-Host [5] - "Add Remote Desktop Connection to the Desktop"
	Write-Host [6] - "Add Sicorfe default background"
	Write-Host [7] - "Rename computer (reboot the system)"
	Write-Host [q] - "Exit `r`n"

	
    $selection = Read-Host "Select an option"
    switch ($selection)
    {
    '1' {
		
		###############################
		##Installation d'applications##
		###############################
		
		#Installation Chrome
		Write-Host "Installing Google Chrome" -ForegroundColor Yellow
		winget install -e --id Google.Chrome | Out-Host
		if($?) { Write-Host "Google Chrome Installed" -ForegroundColor Green }
		
		#Installation 7-Zip
		Write-Host "Installing 7-Zip" -ForegroundColor Yellow
		winget install -e --id 7zip.7zip | Out-Host
		if($?) { Write-Host "7-Zip Installed" -ForegroundColor Green }
		
		#Installation TeamViewer
		Write-Host "Installing TeamViewer" -ForegroundColor Yellow
		winget install -e --id TeamViewer.TeamViewer | Out-Host
		if($?) { Write-Host "TeamViewer Installed" -ForegroundColor Green }
		
		#Installation Acrobat Reader
		Write-Host "Installing Adobe Acrobat Reader" -ForegroundColor Yellow
		winget install -e --id Adobe.Acrobat.Reader.64-bit | Out-Host
		if($?) { Write-Host "Adobe Acrobat Reader Installed" -ForegroundColor Green }
		
		##Installation FortiClientVPN
		##Installation manuelle à cause de l'impossibilité de mettre à jour le paquet
		$url = "https://filestore.fortinet.com/forticlient/downloads/FortiClientVPNSetup_7.0.1.0083_x64.zip.zip"
		} else {
		$url = "https://filestore.fortinet.com/forticlient/downloads/FortiClientVPNSetup_7.0.1.0083.zip"
		}

		##Variables
		$path = $env:TEMP
		$zip = $path + "\FortiClientVPN.zip"
		$msi = $path + "\FortiClientVPN.msi"


		Write-Host "Downloading FortiClientVPN ..."
		Invoke-WebRequest $url -OutFile $zip


		Write-Host "Extracting files from the zip file ..."
		Expand-Archive -LiteralPath $zip -DestinationPath $path


		Write-Host "Installing FortiClientVPN"
		MsiExec.exe /i $msi REBOOT=ReallySuppress /qn

		Write-Host "FortiClientVPN Installed" -ForegroundColor Green
		
    } '2' {
		
		############################
		## Desinstallation McAfee ##
		############################
		
		##Variables
		$McAfeeSoftware = Get-ChildItem HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -like "*McAfee*" }
		$McAfeeSoftware += Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -like "*McAfee*" }
		$McAfeeCheck =
		
		
		Write-Host "Checking for McAfee software (Check 1)..." -ForegroundColor Yellow
		if (($McAfeeSoftware) -ne $null)
		{
			Write-Host "Found McAfee software..." -ForegroundColor Green
			foreach ($Software in @("McAfee Endpoint Security Adaptive Threat Prevention", "McAfee Endpoint Security Web Control",
					"McAfee Endpoint Security Threat Prevention", "McAfee Endpoint Security Firewall", "McAfee Endpoint Security Platform",
					"McAfee VirusScan Enterprise", "McAfee Agent"))
			{
				if ($McAfeeSoftware | Where-Object DisplayName -like $Software)
				{
					$McAfeeSoftware | Where-Object DisplayName -like $Software | ForEach-Object {
						Write-Host "Uninstalling $($_.DisplayName)"
						
						if ($_.uninstallstring -like "msiexec*")
						{
							Write-Debug "Uninstall string: Start-Process $($_.UninstallString.split(' ')[0]) -ArgumentList `"$($_.UninstallString.split(' ', 2)[1]) /qn REBOOT=SUPPRESS`" -Wait"
							Start-Process $_.UninstallString.split(" ")[0] -ArgumentList "$($_.UninstallString.split("  ", 2)[1]) /qn" -Wait
						}
						else
						{
							Write-Debug "Uninstall string: Start-Process $($_.UninstallString) -Wait"
							Start-Process $_.UninstallString -Wait
						}
					}
				}
			}
			Write-Host "Finished removing McAfee." -ForegroundColor Green
		}
		else
		{
			Write-Host "McAfee software not found..." -ForegroundColor Yellow
			Write-Host "Continuing..." -ForegroundColor Green
		}

		## 20200716.x.Temporarily commenting out this portion of the removal.
		Write-Host "Skipping McAfee Check 2..." -ForegroundColor Yellow
		<#
			## Removing Specific McAfee software.
		Write-Host "Checking for McAfee (Check 2)..." -ForegroundColor Yellow
		If ((WMIC product where "Name Like '%%McAfee%%'") -ne "No Instance(s) Available.")
		{
			Write-Host "Removing McAfee VirusScan Enterprise..." -ForegroundColor Yellow
			WMIC product where "description= 'McAfee VirusScan Enterprise' " uninstall
			
			Write-Host "Removing McAfee Agent..." -ForegroundColor Yellow
			WMIC product where "description= 'McAfee Agent' " uninstall
		}
		else
		{
			Write-Host "No removable McAfee software found..." -ForegroundColor Yellow
			Write-Host "Continuing..." -ForegroundColor Green
		}
		#>

		## Attempting to remove other McAfee software that isn't Tamper protected
		Write-Host "Checking for McAfee (Check 3)..." -ForegroundColor Yellow
		if ((Get-Package -Name McAfee*) -ne $null)
		{
			Write-Host "Found McAfee Software..." -ForegroundColor Green
			Write-Host "Removing McAfee software..." -ForegroundColor Yellow
			Get-Package -Name McAfee* | Uninstall-Package -AllVersions -Force
			
		}
		else
		{
			Write-Host "No removable McAfee software found..." -ForegroundColor Yellow
			Write-Host "Continuing..." -ForegroundColor Green
		}
		
    } '3' {
		
		############################
		## Desactivation OneDrive ##
		############################
		
		Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDrive"
		Write-Host "Done"
		
    } '4' {
		
		######################################
		## Activation verouillage numérique ##
		#####################################
		
		Set-ItemProperty -Path 'Registry::HKCU\.DEFAULT\Control Panel\Keyboard' -Name "InitialKeyboardIndicators" -Value "2"
		
		Write-Host "Done"
		
    } '5' {
		
		#############################
		## Copie Bureau à Distance ##
		#############################
		
		##Variables
		$folder     = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Remote Desktop Connection.lnk"
		$desktopW10 = "C:\Users\Public\Public Desktop"
		$desktop    = "C:\Users\Public\Desktop"

		# Win7 ou Win10
		if(Test-Path $desktop){
		  Copy-Item $folder -Destination $desktop -Verbose
		}
    
		if(Test-Path $desktopW10){
		  Copy-Item $folder -Destination $desktopW10 -Verbose
		}
		
		Write-Host "Done"
		
    } '6' {
		
		###########################
		## Changer fond d'écran ##
		#########################
		
		$url = "https://raw.githubusercontent.com/arthur-sicorfe/LSIT/main/asset/wallpaper-sicorfe.png"
		
		if ((Test-Path "c:\users\Public\Pictures\wallpaper-sicorfe.png") -eq $false)
		{
		Invoke-WebRequest $url -OutFile "c:\users\Public\Pictures\wallpaper-sicorfe.png"
		}
		
		Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name Wallpaper -value "c:\users\Public\Pictures\wallpaper-sicorfe.png"
		Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name TileWallpaper -value "0"
		Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name WallpaperStyle -value "10" -Force
		
		Write-Host "Done"
			
    } '7' {
		
		###########################
		## Renommage ordinateur ##
		#########################
		
		$name = Read-Host "Please enter the computer name : "
		Rename-Computer -NewName $name -Restart
    }
    }
    pause
 }
 until ($selection -eq 'q')
 


