Function Priority {
    $ErrorActionPreference = 'SilentlyContinue'
    New-PSDrive -PSProvider Registry -Name HKCU -Root HKEY_CURRENT_USER | Out-Null
    New-PSDrive -PSProvider Registry -Name HKLM -Root HKEY_LOCAL_MACHINE | Out-Null
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
    New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
}

Priority

# The function is here because programs add themselves to the right click menu after loading
    Function RightClickMenu {
        try {
            Write-Host "Editing the right click menu..." -NoNewline
    
            # Old right click menu
            $regPath = "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
            reg.exe add $regPath /f /ve *>$null
    
            $contextMenuPaths = @(
                "HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo", #remove send to
                "HKEY_CLASSES_ROOT\UserLibraryFolder\shellex\ContextMenuHandlers\SendTo", #remove send to
                "HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\ModernSharing", #remove share
                "HKEY_CLASSES_ROOT\*\shell\pintohomefile", #remove favorites
                #remove give access
                "HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\Sharing",
                "HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers\Sharing",
                "HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\Sharing",
                "HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers\Sharing",
                "HKEY_CLASSES_ROOT\LibraryFolder\background\shellex\ContextMenuHandlers\Sharing",
                "HKEY_CLASSES_ROOT\UserLibraryFolder\shellex\ContextMenuHandlers\Sharing",
                #remove previous
                "HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
                "HKEY_CLASSES_ROOT\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
                "HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
                "HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
                #remove "Include in library"
                "HKEY_CLASSES_ROOT\Folder\ShellEx\ContextMenuHandlers\Library Location",
                "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Folder\ShellEx\ContextMenuHandlers\Library Location"
                #remove "copy as path"
                "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\CopyAsPathMenu"
                #remove git
                "HKEY_CLASSES_ROOT\Directory\Background\shell\git_gui",
                "HKEY_CLASSES_ROOT\Directory\Background\shell\git_shell",
                #remove treesize
                "HKEY_CLASSES_ROOT\Directory\Background\shell\TreeSize Free",
                "HKEY_CLASSES_ROOT\Directory\Background\shell\VSCode"
                #remove mpc player
                "HKEY_CLASSES_ROOT\Directory\shell\mplayerc64.enqueue"
                #remove sharex
                "HKEY_CLASSES_ROOT\Directory\shell\ShareX"
                #remove vlc
                "HKEY_CLASSES_ROOT\Directory\shell\AddToPlaylistVLC"
                #remove google drive
                "HKEY_CLASSES_ROOT\GoogleDriveFS.gcsedoc"
                "HKEY_CLASSES_ROOT\GoogleDriveFS.gcsesheet"
                "HKEY_CLASSES_ROOT\GoogleDriveFS.gcseslides"
                "HKEY_CLASSES_ROOT\GoogleDriveFS.gdoc"
                "HKEY_CLASSES_ROOT\GoogleDriveFS.gdraw"
                "HKEY_CLASSES_ROOT\GoogleDriveFS.gdrive"
                "HKEY_CLASSES_ROOT\GoogleDriveFS.gform"
                "HKEY_CLASSES_ROOT\GoogleDriveFS.gjam"
                "HKEY_CLASSES_ROOT\GoogleDriveFS.glink"
                "HKEY_CLASSES_ROOT\GoogleDriveFS.gmaillayout"
                "HKEY_CLASSES_ROOT\GoogleDriveFS.gmap"
                "HKEY_CLASSES_ROOT\GoogleDriveFS.gnote"
                "HKEY_CLASSES_ROOT\GoogleDriveFS.gscript"
                "HKEY_CLASSES_ROOT\GoogleDriveFS.gsheet"
                "HKEY_CLASSES_ROOT\GoogleDriveFS.gsite"
                "HKEY_CLASSES_ROOT\GoogleDriveFS.gslides"
                "HKEY_CLASSES_ROOT\GoogleDriveFS.gtable"
                "HKEY_CLASSES_ROOT\GoogleDriveFS.gvid"
            )

            foreach ($path in $contextMenuPaths) {
                $regPath = $path -replace 'HKCR:\\', 'HKEY_CLASSES_ROOT\' 
                $cmd = "reg delete `"$regPath`" /f"
                Invoke-Expression $cmd *>$null
            }
    
            # New hash menu for right click
            $regpath = "HKEY_CLASSES_ROOT\*\shell\hash"
            $sha256menu = "HKEY_CLASSES_ROOT\*\shell\hash\shell\02menu"
            $md5menu = "HKEY_CLASSES_ROOT\*\shell\hash\shell\03menu"
    
            reg add $regpath /f *>$null
            reg add $regpath /v "MUIVerb" /t REG_SZ /d HASH /f *>$null
            reg add $regpath /v "SubCommands" /t REG_SZ /d """" /f *>$null
            reg add "$regpath\shell" /f *>$null
    
            reg add "$sha256menu" /f *>$null
            reg add "$sha256menu\command" /f *>$null
            reg add "$sha256menu" /v "MUIVerb" /t REG_SZ /d SHA256 /f *>$null
    
            $tempOut = [System.IO.Path]::GetTempFileName()
            $tempErr = [System.IO.Path]::GetTempFileName()
            Start-Process cmd.exe -ArgumentList '/c', 'reg add "HKEY_CLASSES_ROOT\*\shell\hash\shell\02menu\command" /ve /d "powershell -noexit get-filehash -literalpath \"%1\" -algorithm SHA256 | format-list" /f' -NoNewWindow -RedirectStandardOutput $tempOut -RedirectStandardError $tempErr
            Remove-Item $tempOut -ErrorAction Ignore
            Remove-Item $tempErr -ErrorAction Ignore
    
            reg add "$md5menu" /f *>$null
            reg add "$md5menu\command" /f *>$null
            reg add "$md5menu" /v "MUIVerb" /t REG_SZ /d MD5 /f *>$null
    
            $tempOut = [System.IO.Path]::GetTempFileName()
            $tempErr = [System.IO.Path]::GetTempFileName()
            Start-Process cmd.exe -ArgumentList '/c', 'reg add "HKEY_CLASSES_ROOT\*\shell\hash\shell\03menu\command" /ve /d "powershell -noexit get-filehash -literalpath \"%1\" -algorithm MD5 | format-list" /f' -NoNewWindow -RedirectStandardOutput $tempOut -RedirectStandardError $tempErr
            Remove-Item $tempOut -ErrorAction Ignore
            Remove-Item $tempErr -ErrorAction Ignore
    
            # Add Turn Off Display Menu
            $turnOffDisplay = "HKEY_CLASSES_ROOT\DesktopBackground\Shell\TurnOffDisplay"
            reg add $turnOffDisplay /f *>$null
            reg add $turnOffDisplay /v "Icon" /t REG_SZ /d "imageres.dll,-109" /f *>$null
            reg add $turnOffDisplay /v "MUIVerb" /t REG_SZ /d "Turn off display" /f *>$null
            reg add $turnOffDisplay /v "Position" /t REG_SZ /d "Bottom" /f *>$null
            reg add $turnOffDisplay /v "SubCommands" /t REG_SZ /d """" /f *>$null
    
            reg add "$turnOffDisplay\shell" /f *>$null
            $turnOffMenu1 = "$turnOffDisplay\shell\01menu"
            reg add $turnOffMenu1 /f *>$null
            reg add $turnOffMenu1 /v "Icon" /t REG_SZ /d "powercpl.dll,-513" /f *>$null
            reg add $turnOffMenu1 /v "MUIVerb" /t REG_SZ /d "Turn off display" /f *>$null
            reg add "$turnOffMenu1\command" /f *>$null
            reg add "$turnOffMenu1\command" /ve /d 'cmd /c "powershell.exe -Command \"(Add-Type ''[DllImport(\\\"user32.dll\\\")]public static extern int SendMessage(int hWnd,int hMsg,int wParam,int lParam);'' -Name a -Pas)::SendMessage(-1,0x0112,0xF170,2)\""' /f *>$null
    
            $turnOffMenu2 = "$turnOffDisplay\shell\02menu"
            reg add $turnOffMenu2 /f *>$null
            reg add $turnOffMenu2 /v "MUIVerb" /t REG_SZ /d "Lock computer and Turn off display" /f *>$null
            reg add $turnOffMenu2 /v "CommandFlags" /t REG_DWORD /d 0x20 /f *>$null
            reg add $turnOffMenu2 /v "Icon" /t REG_SZ /d "imageres.dll,-59" /f *>$null
            reg add "$turnOffMenu2\command" /f *>$null
            reg add "$turnOffMenu2\command" /ve /d 'cmd /c "powershell.exe -Command \"(Add-Type ''[DllImport(\\\"user32.dll\\\")]public static extern int SendMessage(int hWnd,int hMsg,int wParam,int lParam);'' -Name a -Pas)::SendMessage(-1,0x0112,0xF170,2)\" & rundll32.exe user32.dll, LockWorkStation"' /f *>$null

            # Add "Find Empty Folders"
            $command = 'powershell.exe -NoExit -Command "Get-ChildItem -Path ''%V'' -Directory -Recurse | Where-Object { $_.GetFileSystemInfos().Count -eq 0 } | ForEach-Object { $_.FullName }"'

            $rightclickregpath = @(
                "Registry::HKEY_CLASSES_ROOT\Directory\shell\FindEmptyFolders",
                "Registry::HKEY_CLASSES_ROOT\Directory\shell\FindEmptyFolders\command",
                "Registry::HKEY_CLASSES_ROOT\Directory\Background\shell\FindEmptyFolders",
                "Registry::HKEY_CLASSES_ROOT\Directory\Background\shell\FindEmptyFolders\command",
                "Registry::HKEY_CLASSES_ROOT\Drive\shell\FindEmptyFolders",
                "Registry::HKEY_CLASSES_ROOT\Drive\shell\FindEmptyFolders\command"
            )

            $icon = "imageres.dll,-1025"
            $defaultValue = "Find Empty Folders"

            $rightclickregpath | ForEach-Object {
                New-Item -Path $_ -Force | Out-Null
                Set-ItemProperty -Path $_ -Name "(Default)" -Value $defaultValue
                Set-ItemProperty -Path $_ -Name "Icon" -Value $icon
            }
            
            # Add blocked keys
            $blockedkeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"
            if (-not (Test-Path -Path $blockedkeyPath)) {
                New-Item -Path $blockedkeyPath -Force | Out-Null
            }
            else {
                ##
            }

            New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
            
            # Add to "Boot to UEFI Firmware Settings"
            New-Item -Path "HKCR:\DesktopBackground\Shell\Firmware" -Force | Out-Null
            Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\Firmware" -Name "Icon" -Value "bootux.dll,-1016"
            Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\Firmware" -Name "MUIVerb" -Value "Boot to UEFI Firmware Settings"
            Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\Firmware" -Name "Position" -Value "Top"
        
            New-Item -Path "HKCR:\DesktopBackground\Shell\Firmware\command" -Force | Out-Null
            Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\Firmware\command" -Name "(default)" -Value "powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/s,/c,shutdown /r /fw' -Verb runAs\""

            # Remove "Edit in Notepad"
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{CA6CC9F1-867A-481E-951E-A28C5E4F01EA}" -Value "Edit in Notepad"

            # Remove "Cast to Device"
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" -Value "Play to Menu"

            # Restart Windows Explorer
            taskkill /f /im explorer.exe *>$null
            Start-Sleep 2
            Start-Process "explorer.exe" -ErrorAction Stop
    
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
    
        catch {
            Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
        }
    }
    
    RightClickMenu