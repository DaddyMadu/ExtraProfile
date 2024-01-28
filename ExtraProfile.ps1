$ExtraProfileCurrentVersion = (Get-ItemProperty "HKCU:\SOFTWARE\BlissConsoles").epversion
Write-Host "ExtraProfile $ExtraProfileCurrentVersion"
$UpdateExtraProfile = {
    $ExtraProfileCurrentVersion = (Get-ItemProperty "HKCU:\SOFTWARE\BlissConsoles").epversion
    $ExtraProfileLiveVersion = Invoke-WebRequest -URI 'https://raw.githubusercontent.com/DaddyMadu/ExtraProfile/main/version' | Select-Object -Expand Content
    if ($ExtraProfileLiveVersion -eq $ExtraProfileCurrentVersion) {
    } else {
        Write-Host "ExtraProfile $ExtraProfileLiveVersion update available, current is $ExtraProfileCurrentVersion use update-extrap to update"
    }
}
   $InitializationScript = $executioncontext.invokecommand.NewScriptBlock("$UpdateExtraProfile")
   $JobSplat = @{
       Name = "CheckFEPUpdate"
       InitializationScript = $InitializationScript
   }
   Start-Job @JobSplat -ScriptBlock {
    Param($Value)
    } | Out-Null
   
    Function update-extrap {
        Write-Host "updating your `$extraprofile , please hold on for a second...."
        Invoke-RestMethod 'https://raw.githubusercontent.com/DaddyMadu/ExtraProfile/main/ExtraProfile.ps1' -OutFile ($env:DOCUMENTS+ '\ExtraProfile.ps1')
        $ExtraProfileLiveVersion = Invoke-WebRequest -URI 'https://raw.githubusercontent.com/DaddyMadu/ExtraProfile/main/version' | Select-Object -Expand Content
        New-Item -Path "HKCU:\SOFTWARE\BlissConsoles" >$null -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path "HKCU:\SOFTWARE\BlissConsoles" -Name "epversion" -Type String -Value "$ExtraProfileLiveVersion" -force >$null
        Write-Host "update completed, please reload your `$profile"
    }
    Function vencord {
        Invoke-RestMethod 'https://github.com/Vencord/Installer/releases/latest/download/VencordInstallerCli.exe' -OutFile ($env:DOWNLOADS + '\VencordInstallerCli.exe')
        & dudo ($env:DOWNLOADS + '\VencordInstallerCli.exe') --install
        Remove-Item ($env:DOWNLOADS + '\VencordInstallerCli.exe') -force
    }
# VPN VOIP
Function vpnv {
    if (Test-Path "$env:temp\dmtmp\DaddyMadu-VPN-VOIP.bat")
        {
    Write-Output "Lunching DaddyMadu VPN Script...."
    reg ADD "HKEY_CURRENT_USER\SOFTWARE\DM Windows Optimizer\Updater" /v "Mode" /t REG_SZ /d "1" /f >nul 2>&1
    Start-Process -Verb RunAs cmd.exe -ArgumentList '/c "%temp%\dmtmp\DaddyMadu-VPN-VOIP.bat"'
        } else {
    Write-Output "File not found!, downloading and lunching DaddyMadu VPN..."
    Invoke-RestMethod 'https://github.com/DaddyMadu/Windows-Optimzier/raw/main/DaddyMadu-VPN-VOIP.bat' -OutFile ($env:temp + '\dmtmp\DaddyMadu-VPN-VOIP.bat')
    reg ADD "HKEY_CURRENT_USER\SOFTWARE\DM Windows Optimizer\Updater" /v "Mode" /t REG_SZ /d "1" /f >nul 2>&1
    Start-Process -Verb RunAs cmd.exe -ArgumentList '/c "%temp%\dmtmp\DaddyMadu-VPN-VOIP.bat"'
        }
    }
# VPN Global
    Function vpng {
        if (Test-Path "$env:temp\dmtmp\DaddyMadu-VPN-VOIP.bat")
            {
        Write-Output "Lunching DaddyMadu VPN Script...."
        reg ADD "HKEY_CURRENT_USER\SOFTWARE\DM Windows Optimizer\Updater" /v "Mode" /t REG_SZ /d "2" /f >nul 2>&1
        Start-Process -Verb RunAs cmd.exe -ArgumentList '/c "%temp%\dmtmp\DaddyMadu-VPN-VOIP.bat"'
            } else {
        Write-Output "File not found!, downloading and lunching DaddyMadu VPN..."
        Invoke-RestMethod 'https://github.com/DaddyMadu/Windows-Optimzier/raw/main/DaddyMadu-VPN-VOIP.bat' -OutFile ($env:temp + '\dmtmp\DaddyMadu-VPN-VOIP.bat')
        reg ADD "HKEY_CURRENT_USER\SOFTWARE\DM Windows Optimizer\Updater" /v "Mode" /t REG_SZ /d "2" /f >nul 2>&1
        Start-Process -Verb RunAs cmd.exe -ArgumentList '/c "%temp%\dmtmp\DaddyMadu-VPN-VOIP.bat"'
            }
        }
# scp -P 21098 cpuser@server266.web-hosting.com:/home/cpuser/public_html/error_log C:\Users\Windows_user\Desktop
Function fromserver {
    scp -P 69 root@madu.gg:$($args[0]) $($args[1])
}
# scp -P 21098 C:\Users\Windows_user\Desktop\image.jpg cpuser@server266.web-hosting.com:/home/cpuser/public_html
Function toserver {
    scp -P 69 $($args[0]) root@madu.gg:$($args[1])
}
Function dudo { 
       gsudo --direct --integrity medium -- $args
}
Function choco-list {
	choco list -l -r --id-only
}
Function choco-skip {
if ($args.Count -eq 0) {
	Write-Output "no package name found, please add at least one package name."
} else {
	choco uninstall $args --skip-powershell --skip-autouninstaller
	}
}
Function enable-we {
	if (Test-Path ($env:homedrive + '\MaduScripts\Enable WE Main.bat')) {
Start-Process cmd.exe -FilePath "$env:homedrive\MaduScripts\Enable WE Main.bat" -WindowStyle Hidden -Wait | Out-Null >$null
ipinfo
Write-Output "You are now using WE VDSL Line!"
	} else {
Write-Output "WE VDSL Line file was not found!"
		}
	}
Function enable-vf {
	if (Test-Path ($env:homedrive + '\MaduScripts\Enable VF Main.bat')) {
Start-Process cmd.exe -FilePath "$env:homedrive\MaduScripts\Enable VF Main.bat" -WindowStyle Hidden -Wait | Out-Null >$null
ipinfo
Write-Output "You are now using Vodafone VDSL Line!"
	} else {
Write-Output "Vodafone VDSL Line file was not found!"
		}
	}
	
Function NvidiaTweaks {
       $CheckGPU = wmic path win32_VideoController get name
       if(($CheckGPU -like "*GTX*") -or ($CheckGPU -like "*RTX*")) {
       Write-Output "NVIDIA GTX/RTX Card Detected! Applying Nvidia Power Tweaks..."
       Invoke-WebRequest -Uri "https://git.io/JLP93" -OutFile "$Env:windir\system32\BaseProfile.nip" -ErrorAction SilentlyContinue
       Invoke-WebRequest -Uri "https://git.io/JLP9n" -OutFile "$Env:windir\system32\nvidiaProfileInspector.exe" -ErrorAction SilentlyContinue
       Push-Location
       set-location "$Env:windir\system32\"
       nvidiaProfileInspector.exe /s -load "BaseProfile.nip"
       Pop-Location
       } else {
       Write-Output "Nvidia GTX/RTX Card Not Detected! Skipping..."
       } 
       $errpref = $ErrorActionPreference #save actual preference
       $ErrorActionPreference = "silentlycontinue"	   
       $CheckGPURegistryKey0 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000").DriverDesc
	   $CheckGPURegistryKey1 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001").DriverDesc
	   $CheckGPURegistryKey2 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002").DriverDesc
	   $CheckGPURegistryKey3 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003").DriverDesc
	   $ErrorActionPreference = $errpref #restore previous preference
       if(($CheckGPURegistryKey0 -like "*GTX*") -or ($CheckGPURegistryKey0 -like "*RTX*")) {
	   Write-Output "Nvidia GTX/RTX Card Registry Path 0000 Detected! Applying Nvidia Latency Tweaks..."
	   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "D3PCLatency" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "F1TransitionLatency" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "LOWLATENCY" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "Node3DLowLatency" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "PciLatencyTimerControl" -Type DWord -Value "0x00000020"
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RMDeepL1EntryLatencyUsec" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RmGspcMaxFtuS" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RmGspcMinFtuS" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RmGspcPerioduS" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RMLpwrEiIdleThresholdUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RMLpwrGrIdleThresholdUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RMLpwrGrRgIdleThresholdUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RMLpwrMsIdleThresholdUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "VRDirectFlipDPCDelayUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "VRDirectFlipTimingMarginUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "VRDirectJITFlipMsHybridFlipDelayUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "vrrCursorMarginUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "vrrDeflickerMarginUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "vrrDeflickerMaxUs" -Type DWord -Value 1
	   } elseif(($CheckGPURegistryKey1 -like "*GTX*") -or ($CheckGPURegistryKey1 -like "*RTX*")) {
	   Write-Output "Nvidia GTX/RTX Card Registry Path 0001 Detected! Applying Nvidia Latency Tweaks..."
	   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "D3PCLatency" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "F1TransitionLatency" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "LOWLATENCY" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "Node3DLowLatency" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "PciLatencyTimerControl" -Type DWord -Value "0x00000020"
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RMDeepL1EntryLatencyUsec" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RmGspcMaxFtuS" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RmGspcMinFtuS" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RmGspcPerioduS" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RMLpwrEiIdleThresholdUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RMLpwrGrIdleThresholdUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RMLpwrGrRgIdleThresholdUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RMLpwrMsIdleThresholdUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "VRDirectFlipDPCDelayUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "VRDirectFlipTimingMarginUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "VRDirectJITFlipMsHybridFlipDelayUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "vrrCursorMarginUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "vrrDeflickerMarginUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "vrrDeflickerMaxUs" -Type DWord -Value 1
	   } elseif(($CheckGPURegistryKey2 -like "*GTX*") -or ($CheckGPURegistryKey2 -like "*RTX*")) {
	   Write-Output "Nvidia GTX/RTX Card Registry Path 0002 Detected! Applying Nvidia Latency Tweaks..."
	   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "D3PCLatency" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "F1TransitionLatency" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "LOWLATENCY" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "Node3DLowLatency" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "PciLatencyTimerControl" -Type DWord -Value "0x00000020"
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RMDeepL1EntryLatencyUsec" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RmGspcMaxFtuS" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RmGspcMinFtuS" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RmGspcPerioduS" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RMLpwrEiIdleThresholdUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RMLpwrGrIdleThresholdUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RMLpwrGrRgIdleThresholdUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RMLpwrMsIdleThresholdUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "VRDirectFlipDPCDelayUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "VRDirectFlipTimingMarginUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "VRDirectJITFlipMsHybridFlipDelayUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "vrrCursorMarginUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "vrrDeflickerMarginUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "vrrDeflickerMaxUs" -Type DWord -Value 1
	   } elseif(($CheckGPURegistryKey3 -like "*GTX*") -or ($CheckGPURegistryKey3 -like "*RTX*")) {
	   Write-Output "Nvidia GTX/RTX Card Registry Path 0003 Detected! Applying Nvidia Latency Tweaks..."
	   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "D3PCLatency" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "F1TransitionLatency" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "LOWLATENCY" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "Node3DLowLatency" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "PciLatencyTimerControl" -Type DWord -Value "0x00000020"
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RMDeepL1EntryLatencyUsec" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RmGspcMaxFtuS" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RmGspcMinFtuS" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RmGspcPerioduS" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RMLpwrEiIdleThresholdUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RMLpwrGrIdleThresholdUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RMLpwrGrRgIdleThresholdUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RMLpwrMsIdleThresholdUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "VRDirectFlipDPCDelayUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "VRDirectFlipTimingMarginUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "VRDirectJITFlipMsHybridFlipDelayUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "vrrCursorMarginUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "vrrDeflickerMarginUs" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "vrrDeflickerMaxUs" -Type DWord -Value 1
	   } else {
	   Write-Output "No NVIDIA GTX/RTX Card Registry entry Found! Skipping..."
	   }
}

Function NetworkOptimizations {
       Write-Output "Optimizing Network and applying Tweaks for no throttle and maximum speed!..."
       $errpref = $ErrorActionPreference #save actual preference
       $ErrorActionPreference = "silentlycontinue"
       New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -ErrorAction SilentlyContinue | Out-Null
       New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" -ErrorAction SilentlyContinue | Out-Null
       New-Item -Path "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters" -ErrorAction SilentlyContinue | Out-Null
       Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" -Name "explorer.exe" -Type DWord -Value 10
       Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" -Name "explorer.exe" -Type DWord -Value 10
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "LocalPriority" -Type DWord -Value 4
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "HostsPriority" -Type DWord -Value 5
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "DnsPriority" -Type DWord -Value 6
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "NetbtPriority" -Type DWord -Value 7
       Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortlimit" -Type DWord -Value 0
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" -Name "Do not use NLA" -Type String -Value "1"
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "Size" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 20
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "MaxUserPort" -Type DWord -Value 65534
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpTimedWaitDelay" -Type DWord -Value 30
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL" -Type DWord -Value 64
       Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters" -Name "TCPNoDelay" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\Lsa" -Name "LmCompatibilityLevel" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableAutoDoh" -Type DWord -Value 2
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "MaxNumRssCpus" -Type DWord -Value 4
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableTaskOffload" -Type DWord -Value 0
       Set-NetTCPSetting -SettingName internet -EcnCapability disabled | Out-Null
       Set-NetOffloadGlobalSetting -Chimney disabled | Out-Null
       Set-NetTCPSetting -SettingName internet -Timestamps disabled | Out-Null
       Set-NetTCPSetting -SettingName internet -MaxSynRetransmissions 2 | Out-Null
       Set-NetTCPSetting -SettingName internet -NonSackRttResiliency disabled | Out-Null
       Set-NetTCPSetting -SettingName internet -InitialRto 2000 | Out-Null
       Set-NetTCPSetting -SettingName internet -MinRto 300 | Out-Null
       Set-NetTCPSetting -SettingName Internet -AutoTuningLevelLocal normal | Out-Null
       Set-NetTCPSetting -SettingName internet -ScalingHeuristics disabled | Out-Null
       netsh int tcp set supplemental internet congestionprovider=ctcp | Out-Null
       netsh int tcp set global rss=enabled | Out-Null
       netsh int ip set global taskoffload=enabled | Out-Null
       netsh int tcp set global autotuninglevel=disabled | Out-Null
       Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing disabled | Out-Null
       Set-NetOffloadGlobalSetting -ReceiveSideScaling enabled | Out-Null
       Disable-NetAdapterLso -Name * | Out-Null
       Enable-NetAdapterChecksumOffload -Name * | Out-Null
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Energy-Efficient Ethernet" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Energy Efficient Ethernet" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Energy Efficient Ethernet" -DisplayValue "Off" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Ultra Low Power Mode" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "System Idle Power Saver" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Green Ethernet" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Power Saving Mode" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Gigabit Lite" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "EEE" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Advanced EEE" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "ARP Offload" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "NS Offload" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Large Send Offload v2 (IPv4)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Large Send Offload v2 (IPv6)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "TCP Checksum Offload (IPv4)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "TCP Checksum Offload (IPv6)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "UDP Checksum Offload (IPv4)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "UDP Checksum Offload (IPv6)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Idle Power Saving" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Flow Control" -DisplayValue "Enabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Flow Control" -DisplayValue "Rx & Tx Enabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Interrupt Moderation" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Reduce Speed On Power Down" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Interrupt Moderation Rate" -DisplayValue "Off" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Log Link State Event" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Packet Priority & VLAN" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Packet Priority & VLAN" -DisplayValue "Packet Priority & VLAN Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Priority & VLAN" -DisplayValue "Priority & VLAN Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "IPv4 Checksum Offload" -DisplayValue "Rx & Tx Enabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Jumbo Frame" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Maximum Number of RSS Queues" -DisplayValue "2 Queues" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Receive Side Scaling" -DisplayValue "Enabled" -ErrorAction SilentlyContinue
       $ErrorActionPreference = $errpref #restore previous preference
       if ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -ne 2)
{
    $adapters = Get-NetAdapter -Physical | Get-NetAdapterPowerManagement | Where-Object -FilterScript {$_.AllowComputerToTurnOffDevice -ne "Unsupported"}
    foreach ($adapter in $adapters)
    {
        $adapter.AllowComputerToTurnOffDevice = "Disabled"
        $adapter | Set-NetAdapterPowerManagement
    }
}
       Start-Sleep -s 2
	   $errpref = $ErrorActionPreference #save actual preference
$ErrorActionPreference = "silentlycontinue"
$NetworkIDS = @(
(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\*").PSChildName
)
    foreach ($NetworkID in $NetworkIDS) {
	Write-Output "Disabling Nagles Algorithm..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$NetworkID" -Name "TcpAckFrequency" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$NetworkID" -Name "TCPNoDelay" -Type DWord -Value 1
}
$ErrorActionPreference = $errpref #restore previous preference
$errpref = $ErrorActionPreference #save actual preference
$ErrorActionPreference = "silentlycontinue"
Write-Output "Setting network adapter RSS..."
	$PhysicalAdapters = Get-WmiObject -Class Win32_NetworkAdapter|Where-Object{$_.PNPDeviceID -notlike "ROOT\*" -and $_.Manufacturer -ne "Microsoft" -and $_.ConfigManagerErrorCode -eq 0 -and $_.ConfigManagerErrorCode -ne 22}
	
	Foreach($PhysicalAdapter in $PhysicalAdapters)
	{
		$DeviceID = $PhysicalAdapter.DeviceID
		If([Int32]$DeviceID -lt 10)
		{
			$AdapterDeviceNumber = "000"+$DeviceID
		}
		Else
		{
			$AdapterDeviceNumber = "00"+$DeviceID
		}
		$KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\$AdapterDeviceNumber"
		$KeyPath2 = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\$AdapterDeviceNumber\Ndi\params\*RSS\Enum"
		$KeyPath3 = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\$AdapterDeviceNumber\Ndi\params\*RSS"
		$KeyPath4 = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\$AdapterDeviceNumber\Ndi\params\*NumRssQueues\Enum"
		$KeyPath5 = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\$AdapterDeviceNumber\Ndi\params\*NumRssQueues"
		$KeyPath6 = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\$AdapterDeviceNumber\Ndi\params\*ReceiveBuffers"
		$KeyPath7 = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\$AdapterDeviceNumber\Ndi\params\*TransmitBuffers"
		
		If(Test-Path -Path $KeyPath)
			{
					new-Item -Path $KeyPath2 -Force | Out-Null
					new-Item -Path $KeyPath4 -Force | Out-Null
					Set-ItemProperty -Path $KeyPath -Name "*NumRssQueues" -Type String -Value 2 | Out-Null
					Set-ItemProperty -Path $KeyPath -Name "*RSS" -Type String -Value 1 | Out-Null
					Set-ItemProperty -Path $KeyPath -Name "*RSSProfile" -Type String -Value 4 | Out-Null
					Set-ItemProperty -Path $KeyPath -Name "*RssBaseProcNumber" -Type String -Value 2 | Out-Null
					Set-ItemProperty -Path $KeyPath -Name "*MaxRssProcessors" -Type String -Value 4 | Out-Null
					Set-ItemProperty -Path $KeyPath -Name "*NumaNodeId" -Type String -Value 0 | Out-Null
					Set-ItemProperty -Path $KeyPath -Name "*RssBaseProcGroup" -Type String -Value 0 | Out-Null
					Set-ItemProperty -Path $KeyPath -Name "*RssMaxProcNumber" -Type String -Value 4 | Out-Null
					Set-ItemProperty -Path $KeyPath -Name "*RssMaxProcGroup" -Type String -Value 0 | Out-Null
					Set-ItemProperty -Path $KeyPath -Name "*ReceiveBuffers" -Type String -Value 2048 | Out-Null
					Set-ItemProperty -Path $KeyPath -Name "*TransmitBuffers" -Type String -Value 4096 | Out-Null
					New-ItemProperty -Path $KeyPath3 -Name "default" -Type String -Value 1 | Out-Null
					New-ItemProperty -Path $KeyPath3 -Name "ParamDesc" -Type String -Value "Receive Side Scaling" | Out-Null
					New-ItemProperty -Path $KeyPath3 -Name "type" -Type String -Value "enum" | Out-Null
					New-ItemProperty -Path $KeyPath2 -Name "0" -Type String -Value "Disabled" | Out-Null
					New-ItemProperty -Path $KeyPath2 -Name "1" -Type String -Value "Enabled" | Out-Null
					New-ItemProperty -Path $KeyPath4 -Name "1" -Type String -Value "1 Queue" | Out-Null
					New-ItemProperty -Path $KeyPath4 -Name "2" -Type String -Value "2 Queue" | Out-Null
					New-ItemProperty -Path $KeyPath4 -Name "3" -Type String -Value "3 Queue" | Out-Null
					New-ItemProperty -Path $KeyPath4 -Name "4" -Type String -Value "4 Queue" | Out-Null
					New-ItemProperty -Path $KeyPath5 -Name "default" -Type String -Value "2" | Out-Null
					New-ItemProperty -Path $KeyPath5 -Name "ParamDesc" -Type String -Value "Maximum Number of RSS Queues" | Out-Null
					New-ItemProperty -Path $KeyPath5 -Name "type" -Type String -Value "enum" | Out-Null
					Set-ItemProperty -Path $KeyPath6 -Name "Max" -Type String -Value 6144 | Out-Null
					Set-ItemProperty -Path $KeyPath6 -Name "Default" -Type String -Value 2048 | Out-Null
					Set-ItemProperty -Path $KeyPath7 -Name "Max" -Type String -Value 6144 | Out-Null
					Set-ItemProperty -Path $KeyPath7 -Name "Default" -Type String -Value 4096 | Out-Null
		}
				Else
		{
			Write-Host "The path ($KeyPath) not found."
		}
	}
 $ErrorActionPreference = $errpref #restore previous preference
}
