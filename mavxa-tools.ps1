$currentVersion = "1.1.0" # correct version

function Check-ForUpdates {
    # URL
    $repoUrl = "https://api.github.com/repos/mavxa/mavxa-tools/releases/latest"

    try {
        $latestRelease = Invoke-RestMethod -Uri $repoUrl -ErrorAction Stop
        $latestVersion = $latestRelease.tag_name -replace 'v', ''

        if ([version]$latestVersion -gt [version]$currentVersion) {
            Write-Host "A new version is available: $latestVersion" -ForegroundColor Yellow
            Write-Host "You can download it from the link: $($latestRelease.html_url)" -ForegroundColor Cyan

            $downloadChoice = Read-Host "Do you want to download the update? (Y/N)"
            if ($downloadChoice -eq 'Y' -or $downloadChoice -eq 'y') {
                Start-Process $latestRelease.html_url
            }
        } else {
            Write-Host "You have the latest version installed. ($currentVersion)." -ForegroundColor Green
        }
    } catch {
        Write-Host "Couldn't check for updates: $_" -ForegroundColor Red
    }
}
# Window Settings
$Host.UI.RawUI.WindowTitle = "mavxa-tools"

# Function for automatic verification of admin rights and promotion if necessary
function Check-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "The script is not running as an administrator. Restart attempt..." -ForegroundColor Yellow
        
        $ps = (Get-Process -Id $PID).Path
        if (-not $ps -or -not (Test-Path $ps)) {
            Write-Host "The path to the PowerShell executable could not be determined." -ForegroundColor Red
            exit
        }

        Start-Process $ps -Verb RunAs -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`""
        exit
    } else {
        Write-Host "The script is running with administrator rights." -ForegroundColor Cyan
    }
}

Check-Admin

# Setting up window settings
$Host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.Size(64,3000)
$Host.UI.RawUI.WindowSize = New-Object System.Management.Automation.Host.Size(64,23)
$Host.UI.RawUI.WindowPosition = New-Object System.Management.Automation.Host.Coordinates(0,0)
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "DarkGreen"
Clear-Host

# Function for checking and setting the execution policy
function Ensure-ExecutionPolicy {
    $desiredPolicy = "RemoteSigned"
    $currentPolicy = Get-ExecutionPolicy -Scope CurrentUser

    if ($currentPolicy -ne $desiredPolicy) {
        try {
            Set-ExecutionPolicy -ExecutionPolicy $desiredPolicy -Scope CurrentUser -Force
            Write-Host "Execution policy successfully changed to $desiredPolicy." -ForegroundColor Green
        } catch {
            Write-Host "Failed to change execution policy. Please run the script as an administrator." -ForegroundColor Red
            exit
        }
    } else {
        Write-Host "Current execution policy: $currentPolicy" -ForegroundColor Cyan
    }
}

# Function for logging actions
function Log-Action {
    param (
        [string]$Action
    )
    $logPath = "C:\Windows\Temp\log-mavxa.txt"
    $logDir = Split-Path $logPath
    if (-not (Test-Path $logDir)) {
        try {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            Write-Host "Created log directory at $logDir." -ForegroundColor Green
        } catch {
            Write-Host "Failed to create log directory at $logDir. Please check permissions." -ForegroundColor Red
            exit
        }
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    try {
        "$timestamp - $Action" | Out-File -FilePath $logPath -Append -ErrorAction Stop
    } catch {
        Write-Host "Failed to write to log file: $_" -ForegroundColor Red
    }
}

Ensure-ExecutionPolicy

# Delay for ASCII art
$delay = 0.5

$asciiArt = @(
" _____ ______   ________  ___      ___ ___    ___ ________     ",
"|\   _ \  _   \|\   __  \|\  \    /  /|\  \  /  /|\   __  \    ",
"\ \  \\\__\ \  \ \  \|\  \ \  \  /  / \ \  \/  / | \  \|\  \   ",
" \ \  \\|__| \  \ \   __  \ \  \/  / / \ \    / / \ \   __  \  ",
"  \ \  \    \ \  \ \  \ \  \ \    / /   /     \/   \ \  \ \  \ ",
"   \ \__\    \ \__\ \__\ \__\ \__/ /   /  /\   \    \ \__\ \__\",
"    \|__|     \|__|\|__|\|__|\|__|/   /__/ /\ __\    \|__|\|__|",
"                                      |__|/ \|__|              ",
"     $currentVersion"
)

function Show-PCInformation {
    Write-Host "`nPC Information:`n" -ForegroundColor Cyan
    try {
        Get-ComputerInfo | Format-List
    } catch {
        Write-Host "Failed to retrieve PC information." -ForegroundColor Red
    }
    Pause
}

function Show-NetworkInformation {
    Write-Host "`nNetwork Information:`n" -ForegroundColor Cyan
    try {
        Get-NetAdapter | Select-Object Name,Status,MACAddress,LinkSpeed | Format-Table -AutoSize
        Write-Host "`nIP Configuration:`n" -ForegroundColor Cyan
        ipconfig /all
    } catch {
        Write-Host "Failed to retrieve network information." -ForegroundColor Red
    }
    Pause
}

function Show-DiskSpace {
    Write-Host "`nDisk Space Information:`n" -ForegroundColor Cyan
    try {
        $physicalDisks = Get-PhysicalDisk | Select-Object DeviceId,MediaType,Size,SerialNumber,HealthStatus,FirmwareVersion,BusType,Manufacturer,Model
        $logicalDisks = Get-Disk | Where-Object PartitionStyle -ne 'RAW' | Select-Object Number,FriendlyName,SerialNumber,Size,MediaType,PartitionStyle,HealthStatus,OperationalStatus
        $volumes = Get-Volume | Select-Object DriveLetter,FileSystem,HealthStatus,SizeRemaining,Size,FileSystemLabel,MountPoint

        foreach ($disk in $logicalDisks) {
            Write-Host "Disk Number: $($disk.Number)" -ForegroundColor Yellow
            Write-Host "Friendly Name: $($disk.FriendlyName)"
            Write-Host "Serial Number: $($disk.SerialNumber)"
            Write-Host "Size: $([math]::Round($disk.Size / 1GB, 2)) GB"
            Write-Host "Media Type: $($disk.MediaType)"
            Write-Host "Partition Style: $($disk.PartitionStyle)"
            Write-Host "Health Status: $($disk.HealthStatus)"
            Write-Host "Operational Status: $($disk.OperationalStatus)"

            $physDisk = $physicalDisks | Where-Object { $_.DeviceId -eq $disk.Number }
            if ($physDisk) {
                Write-Host "Physical Disk Media Type: $($physDisk.MediaType)"
                Write-Host "Physical Disk Health Status: $($physDisk.HealthStatus)"
                Write-Host "Physical Disk Bus Type: $($physDisk.BusType)"
                Write-Host "Physical Disk Firmware Version: $($physDisk.FirmwareVersion)"
                Write-Host "Manufacturer: $($physDisk.Manufacturer)"
                Write-Host "Model: $($physDisk.Model)"
            }

            $partitions = Get-Partition -DiskNumber $disk.Number | Select-Object PartitionNumber,DriveLetter,Size,Type,GptType,IsBoot,IsSystem,IsActive,IsReadOnly,AccessPaths
            if ($partitions) {
                Write-Host "Partitions:"
                foreach ($partition in $partitions) {
                    Write-Host "  Partition Number: $($partition.PartitionNumber)"
                    Write-Host "  Drive Letter: $($partition.DriveLetter)"
                    Write-Host "  Size: $([math]::Round($partition.Size / 1GB, 2)) GB"
                    Write-Host "  Type: $($partition.Type)"
                    Write-Host "  GPT Type: $($partition.GptType)"
                    Write-Host "  Is Boot: $($partition.IsBoot)"
                    Write-Host "  Is System: $($partition.IsSystem)"
                    Write-Host "  Is Active: $($partition.IsActive)"
                    Write-Host "  Is ReadOnly: $($partition.IsReadOnly)"
                    Write-Host "  Access Paths: $($partition.AccessPaths -join ', ')"
                    Write-Host "  -----------------------------" -ForegroundColor DarkGray
                }
            } else {
                Write-Host "No partitions found on this disk." -ForegroundColor DarkGray
            }

            $diskVolumes = $volumes | Where-Object { $_.DriveLetter -ne $null -and ($_.DriveLetter -in (Get-Partition -DiskNumber $disk.Number | Select-Object -ExpandProperty DriveLetter)) }
            if ($diskVolumes) {
                Write-Host "Volumes:"
                $diskVolumes | Format-Table -AutoSize
            } else {
                Write-Host "No volumes found on this disk." -ForegroundColor DarkGray
            }

            Write-Host "-------------------------------" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "An error occurred while retrieving disk information: $_" -ForegroundColor Red
    }
    Pause
}

function Show-ProcessInformation {
    Write-Host "`nProcess Information:`n" -ForegroundColor Cyan
    try {
        Get-Process | Sort-Object -Descending WS | Select-Object -First 20 | Format-Table Id,ProcessName,CPU,WS -AutoSize
    } catch {
        Write-Host "Failed to retrieve process information." -ForegroundColor Red
    }
    Pause
}

function Show-ServiceInformation {
    Write-Host "`nService Information:`n" -ForegroundColor Cyan
    try {
        Get-Service | Where-Object { $_.Status -eq 'Running' } | Sort-Object DisplayName | Select-Object DisplayName,Status,StartType | Format-Table -AutoSize
    } catch {
        Write-Host "Failed to retrieve service information." -ForegroundColor Red
    }
    Pause
}

function Show-EventLogs {
    Write-Host "`nSystem Event Logs:`n" -ForegroundColor Cyan
    try {
        Get-EventLog -LogName System -Newest 20 | Select-Object TimeGenerated,EntryType,Source,EventID,Message | Format-Table -AutoSize
    } catch {
        Write-Host "Failed to retrieve event logs." -ForegroundColor Red
    }
    Pause
}

function Change-UserPassword {
    Write-Host "`nAll local user accounts:`n" -ForegroundColor Cyan
    try {
        $users = Get-LocalUser | Select-Object Name, Enabled, LastPasswordSet
        $users | Format-Table -AutoSize
    } catch {
        Write-Host "Failed to retrieve local users." -ForegroundColor Red
        return
    }
    $username = Read-Host "Enter the username (or 'exit' to cancel)"
    if ($username.ToLower() -eq "exit") {
        Write-Host "Cancelling password change."
        return
    }

    $user = $users | Where-Object { $_.Name -eq $username }
    if (-not $user) {
        Write-Host "User '$username' does not exist." -ForegroundColor Red
        return
    }

    $newPassword = Read-Host "Enter new password" -AsSecureString
    $confirmPassword = Read-Host "Confirm new password" -AsSecureString

    $newPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newPassword))
    $confirmPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmPassword))

    if ($newPasswordPlain -ne $confirmPasswordPlain) {
        Write-Host "Passwords do not match. Please try again." -ForegroundColor Red
        return
    }

    try {
        Set-LocalUser -Name $username -Password $newPassword
        Write-Host "Password for user '$username' has been successfully changed." -ForegroundColor Green
        Log-Action "Password for user '$username' was changed to '$newPasswordPlain'."
    } catch {
        Write-Host "Failed to change password for user '$username': $_" -ForegroundColor Red
    }
    Pause
}

function Run-ActivatedWinCommand {
    Write-Host "`nRunning Activated.Win Command:`n" -ForegroundColor Cyan
    try {
        irm https://get.activated.win | iex
        Write-Host "Command executed successfully." -ForegroundColor Green
        Log-Action "Executed irm https://get.activated.win | iex command."
    } catch {
        Write-Host "Failed to execute command: $_" -ForegroundColor Red
    }
    Pause
}

function Run-ChristitusCommand {
    Write-Host "`nRunning Christitus Win Command:`n" -ForegroundColor Cyan
    try {
        irm -useb https://christitus.com/win | iex
        Write-Host "Command executed successfully." -ForegroundColor Green
        Log-Action "Executed irm -useb https://christitus.com/win | iex command."
    } catch {
        Write-Host "Failed to execute command: $_" -ForegroundColor Red
    }
    Pause
}

function Show-UpdateMenu {
    $submenuRunning = $true
    while ($submenuRunning) {
        Clear-Host
        foreach ($line in $asciiArt) {
            Write-Host $line -ForegroundColor Green
            Start-Sleep -Seconds $delay
        }

        Write-Host "Mavxa-Tools - Version $currentVersion" -ForegroundColor Cyan
        Write-Host "1. check updates"
        Write-Host "2. other options..."
        Write-Host "0. exit"

        $choice = Read-Host "Select an option"

        switch ($choice) {
            "1" {
                Check-ForUpdates
                Pause
            }
            "2" {
                # Другие опции...
            }
            "0" {
                Log-Action "Return to main menu from submenu"
                $submenuRunning = $false
            }
            default {
                Write-Host "Wrong choice. Try again." -ForegroundColor Red
                Pause
            }
        }
    }
}

function Show-ToolsSubmenu {
    $submenuRunning = $true
    while ($submenuRunning) {
        Clear-Host
        foreach ($line in $asciiArt) {
            Write-Host $line -ForegroundColor Green
            Start-Sleep -Seconds $delay
        }

        Write-Host "Tools Menu:" -ForegroundColor Cyan
        Write-Host "1. Run Activated.Win Command"
        Write-Host "2. Run Christitus Win Command"
        Write-Host "type 'clear' to clear screen and redraw ASCII" -ForegroundColor Cyan
        Write-Host "type 'exit' to return to main menu" -ForegroundColor Red

        $subChoice = Read-Host "/"

        switch ($subChoice.ToLower()) {
            "1" {
                Log-Action "Run Activated.Win Command from submenu"
                Run-ActivatedWinCommand
            }
            "2" {
                Log-Action "Run Christitus Win Command"
                Run-ChristitusCommand
            }
            "clear"{
                Log-Action "Clear Screen and Redraw ASCII in submenu"
            }
            "exit"{
                Log-Action "Return to main menu from submenu"
                $submenuRunning = $false
            }
            default {
                Log-Action "Invalid Choice in submenu: $subChoice"
                Write-Host "Invalid choice. Please try again." -ForegroundColor Red
            }
        }
    }
}

$running = $true

while ($running) {
    # Before displaying the menu, clear the screen and print the ASCII art again
    Clear-Host
    foreach ($line in $asciiArt) {
        Write-Host $line -ForegroundColor Green
        Start-Sleep -Seconds $delay
    }

    Write-Host "`nChoose an option:" -ForegroundColor Cyan
    Write-Host "1. Show PC Information"
    Write-Host "2. Show Network Information"
    Write-Host "3. Show Disk Space Information"
    Write-Host "4. Show Process Information"
    Write-Host "5. Show Service Information"
    Write-Host "6. Show Event Logs"
    Write-Host "7. Change User Password"
    Write-Host "type 'update' to show updates" -ForegroundColor Cyan
    Write-Host "type 'tools' to  Additional Tools Menu" -ForegroundColor Cyan
    Write-Host "type 'exit' to quit" -ForegroundColor Red

    $choice = Read-Host "/"

    switch ($choice.ToLower()) {
        "1" {
            Log-Action "Show PC Information"
            Show-PCInformation
        }
        "2" {
            Log-Action "Show Network Information"
            Show-NetworkInformation
        }
        "3" {
            Log-Action "Show Disk Space Information"
            Show-DiskSpace
        }
        "4" {
            Log-Action "Show Process Information"
            Show-ProcessInformation
        }
        "5" {
            Log-Action "Show Service Information"
            Show-ServiceInformation
        }
        "6" {
            Log-Action "Show Event Logs"
            Show-EventLogs
        }
        "7" {
            Log-Action "Change User Password"
            Change-UserPassword
        }
        "update" {
            log-Action "Show updates"
            Show-UpdateMenu
        }
        "tools" {
            Log-Action "Enter Additional Tools Submenu"
            Show-ToolsSubmenu
        }
        "clear" {
            Log-Action "Clear Screen and Redraw ASCII in main menu"
        }
        "exit" {
            $confirm = Read-Host "Goodbye, mavxa? (Y/N)"
            if ($confirm -eq "y" -or $confirm -eq "Y") {
                Log-Action "Exit"
                Write-Host "Goodbye, mavxa!" -ForegroundColor Green
                $running = $false
            } else {
                Write-Host "Returning to menu." -ForegroundColor Yellow
            }
        }
        default {
            Log-Action "Invalid Choice: $choice"
            Write-Host "Invalid choice. Please try again." -ForegroundColor Red
        }
    }
}
