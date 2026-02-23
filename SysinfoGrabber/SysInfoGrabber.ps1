# Get-SystemInventory.ps1
# Collects installed programs, device drivers, and event logs
# Saves CSVs + generates a styled HTML viewer

# Stay open on any terminating error
trap {
    Write-Host "`n[ERROR] $_" -ForegroundColor Red
    Write-Host "`nScript encountered an error. Press any key to exit..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

# ================================================================
# CONFIGURATION - Edit this section to customise output location
# ================================================================
$outputBase = "C:\user\somepath\xyz\Sysinfo_Grabber\Storage\"
# ================================================================

# Ensure output directory exists
if (-not (Test-Path $outputBase)) {
    New-Item -ItemType Directory -Path $outputBase -Force | Out-Null
    Write-Host "Created output folder: $outputBase" -ForegroundColor Cyan
}

# File name: Hostname_<timestamp>_SysInfoGrabber.html (no subfolder)
$fileStamp         = $env:COMPUTERNAME + "_" + (Get-Date -Format "yyyyMMdd_HHmmss") + "_SysInfoGrabber"
$htmlPath          = Join-Path $outputBase "$fileStamp.html"

# Temp folder for intermediate files (CSVs, battery report) - cleaned up at end
$outputPath        = Join-Path $env:TEMP "$fileStamp"
New-Item -ItemType Directory -Path $outputPath -Force | Out-Null

Write-Host "Output file : $htmlPath" -ForegroundColor Cyan

$csvPrograms       = "$outputPath\InstalledPrograms.csv"
$csvDrivers        = "$outputPath\SystemDrivers.csv"
$csvEvents         = "$outputPath\EventLogs.csv"
$csvUpdates        = "$outputPath\WindowsUpdates.csv"
$batteryReportPath = "$outputPath\battery-report.html"

# ================================================================
# 0. SYSTEM INFO
# ================================================================
$hostname   = $env:COMPUTERNAME
$osInfo     = Get-CimInstance -ClassName Win32_OperatingSystem
$winCaption = [string]$osInfo.Caption
$winBuild   = [string]$osInfo.BuildNumber
$winVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
$winFullVer = "$winCaption (Version $winVersion, Build $winBuild)"

# OS install date
$osInstallDate = try { ([datetime]$osInfo.InstallDate).ToString("MMMM d, yyyy") } catch { "" }

# Last boot time + uptime
$lastBoot     = try { ([datetime]$osInfo.LastBootUpTime) } catch { $null }
$lastBootStr  = if ($lastBoot) { $lastBoot.ToString("MMMM d, yyyy h:mm tt") } else { "" }
$uptimeHours  = if ($lastBoot) { [math]::Round((New-TimeSpan -Start $lastBoot -End (Get-Date)).TotalHours, 1) } else { 0 }
$uptimeStr    = if ($lastBoot) {
    $ts = New-TimeSpan -Start $lastBoot -End (Get-Date)
    $parts = @()
    if ($ts.Days)    { $parts += "$($ts.Days)d" }
    if ($ts.Hours)   { $parts += "$($ts.Hours)h" }
    if ($ts.Minutes) { $parts += "$($ts.Minutes)m" }
    ($parts -join " ") + " ago"
} else { "" }
$bootOld      = $uptimeHours -gt 24   # flag for red pill

# Hardware info
$csInfo       = Get-CimInstance -ClassName Win32_ComputerSystem
$biosInfo     = Get-CimInstance -ClassName Win32_BIOS
$hwMake       = [string]$csInfo.Manufacturer
$hwModel      = [string]$csInfo.Model
$hwSerial     = [string]$biosInfo.SerialNumber
$hwBiosVer    = [string]$biosInfo.SMBIOSBIOSVersion
$hwBiosDate   = try { ([datetime]$biosInfo.ReleaseDate).ToString("MMMM d, yyyy") } catch { [string]$biosInfo.ReleaseDate }
$biosDisplay  = if ($hwBiosDate) { "$hwBiosVer  ($hwBiosDate)" } else { $hwBiosVer }
$isDell       = $hwMake -match 'Dell'  # used later for clickable serial

# Pull full ipconfig /all equivalent data
$allAdapters    = Get-NetAdapter | Sort-Object Name
$allIPConfigs   = Get-NetIPConfiguration
$allIPAddresses = Get-NetIPAddress
$allDnsServers  = Get-DnsClientServerAddress
$dnsGlobalCfg   = Get-DnsClient | Select-Object -First 1
$hostFQDN       = try { [System.Net.Dns]::GetHostEntry('').HostName } catch { "" }

# Global info (mirrors the top of ipconfig /all)
$globalInfo = @{
    "Host Name"            = $hostname
    "FQDN"                 = $hostFQDN
    "Primary DNS Suffix"   = [string](Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters").Domain
    "Node Type"            = switch ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -ErrorAction SilentlyContinue).NodeType) {
                                 1 { "Broadcast" } 2 { "Peer-Peer" } 4 { "Mixed" } 8 { "Hybrid (default)" } default { "Unknown" } }
    "IP Routing Enabled"   = [string](Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ErrorAction SilentlyContinue).IPEnableRouter
    "WINS Proxy Enabled"   = "No"
    "DNS Suffix Search List"= ([string](Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ErrorAction SilentlyContinue).SearchList)
}

function EscJ($s) { ([string]$s) -replace '\\','\\' -replace '"','\"' -replace "`r`n",' ' -replace "`n",' ' }

$ipJsonLines = foreach ($adapter in $allAdapters) {
    $ifIdx   = $adapter.ifIndex
    $ipCfg   = $allIPConfigs   | Where-Object { $_.InterfaceIndex -eq $ifIdx }
    $dnsEntry= $allDnsServers  | Where-Object { $_.InterfaceIndex -eq $ifIdx }

    # IPv4 addresses with subnet mask
    $ipv4Entries = $allIPAddresses | Where-Object { $_.InterfaceIndex -eq $ifIdx -and $_.AddressFamily -eq 'IPv4' } |
        ForEach-Object {
            $prefix = $_.PrefixLength
            # Convert prefix length to dotted subnet mask
            $mask = if ($prefix -ge 0 -and $prefix -le 32) {
                $bits = ('1' * $prefix).PadRight(32,'0')
                "$([Convert]::ToInt32($bits.Substring(0,8),2)).$([Convert]::ToInt32($bits.Substring(8,8),2)).$([Convert]::ToInt32($bits.Substring(16,8),2)).$([Convert]::ToInt32($bits.Substring(24,8),2))"
            } else { "" }
            "$($_.IPAddress) (Mask: $mask)"
        }

    # IPv6 addresses with prefix and type
    $ipv6Entries = $allIPAddresses | Where-Object { $_.InterfaceIndex -eq $ifIdx -and $_.AddressFamily -eq 'IPv6' } |
        ForEach-Object {
            $type = switch -Regex ($_.IPAddress) {
                "^fe80" { "Link-local" }
                "^fd"   { "Unique local" }
                "^::1"  { "Loopback" }
                default { "Global" }
            }
            "$($_.IPAddress)/$($_.PrefixLength) ($type)"
        }

    # Gateways
    $gw4 = ($ipCfg.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) -join ", "
    $gw6 = ($ipCfg.IPv6DefaultGateway | ForEach-Object { $_.NextHop }) -join ", "

    # DNS
    $dns4 = ($dnsEntry | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses }) -join ", "
    $dns6 = ($dnsEntry | Where-Object { $_.AddressFamily -eq 23 } | ForEach-Object { $_.ServerAddresses }) -join ", "

    # DHCP info
    $dhcpEnabled = $adapter.InterfaceOperationalStatus -ne $null
    $dhcpObj     = $allIPAddresses | Where-Object { $_.InterfaceIndex -eq $ifIdx -and $_.AddressFamily -eq 'IPv4' -and $_.PrefixOrigin -eq 'Dhcp' } | Select-Object -First 1
    $dhcpStatus  = if ($dhcpObj) { "Yes" } else { "No" }
    $dhcpServer  = try { [string](Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.InterfaceIndex -eq $ifIdx }).DHCPServer } catch { "" }
    $dhcpLeaseObt= try { $cfg = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.InterfaceIndex -eq $ifIdx }
                         if ($cfg.DHCPLeaseObtained) { ([datetime]$cfg.DHCPLeaseObtained).ToString("MMMM d, yyyy h:mm tt") } else { "" } } catch { "" }
    $dhcpLeaseExp= try { $cfg = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.InterfaceIndex -eq $ifIdx }
                         if ($cfg.DHCPLeaseExpires)  { ([datetime]$cfg.DHCPLeaseExpires).ToString("MMMM d, yyyy h:mm tt")  } else { "" } } catch { "" }

    # WINS + DHCPv6 + NetBIOS (via WMI)
    $winsCfg     = try { Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.InterfaceIndex -eq $ifIdx } } catch { $null }
    $winsPrimary = [string]$winsCfg.WINSPrimaryServer
    $winsSecond  = [string]$winsCfg.WINSSecondaryServer
    $netbiosOpt  = $winsCfg.TcpipNetbiosOptions
    $netbiosTxt  = switch ($netbiosOpt) {
        0 { "Default (via DHCP)" } 1 { "Enabled" } 2 { "Disabled" } default { "" }
    }

    # DHCPv6 IAID and Client DUID from registry
    $dhcpv6Iaid = ""
    $dhcpv6Duid = ""
    try {
        $regBase = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces"
        # Find sub-key matching this adapter's GUID
        $adapterGuid = (Get-NetAdapter -InterfaceIndex $ifIdx -ErrorAction SilentlyContinue).InterfaceGuid
        if ($adapterGuid) {
            $regPath = "$regBase\$adapterGuid"
            if (Test-Path $regPath) {
                $regVals = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
                if ($regVals.Dhcpv6IAID)     { $dhcpv6Iaid = [string]$regVals.Dhcpv6IAID }
                if ($regVals.Dhcpv6ClientDuid) {
                    $duidBytes = $regVals.Dhcpv6ClientDuid
                    $dhcpv6Duid = ($duidBytes | ForEach-Object { $_.ToString("X2") }) -join "-"
                }
            }
        }
    } catch { }

    # Adapter details
    $speed = if ($adapter.LinkSpeed) { $adapter.LinkSpeed } else { "" }
    $mtu   = try { [string](Get-NetIPInterface -InterfaceIndex $ifIdx -AddressFamily IPv4 -ErrorAction SilentlyContinue).NlMtu } catch { "" }
    $dnsSuffix = [string]$ipCfg.NetProfile.Name

    "  {" +
    "`"name`":`"$(EscJ $adapter.Name)`"," +
    "`"description`":`"$(EscJ $adapter.InterfaceDescription)`"," +
    "`"type`":`"$(EscJ $adapter.InterfaceType)`"," +
    "`"status`":`"$(EscJ $adapter.Status)`"," +
    "`"mac`":`"$(EscJ $adapter.MacAddress)`"," +
    "`"speed`":`"$(EscJ $speed)`"," +
    "`"mtu`":`"$mtu`"," +
    "`"dhcp`":`"$dhcpStatus`"," +
    "`"dhcpServer`":`"$(EscJ $dhcpServer)`"," +
    "`"dhcpLeaseObtained`":`"$(EscJ $dhcpLeaseObt)`"," +
    "`"dhcpLeaseExpires`":`"$(EscJ $dhcpLeaseExp)`"," +
    "`"ipv4`":`"$(EscJ ($ipv4Entries -join ' | '))`"," +
    "`"ipv6`":`"$(EscJ ($ipv6Entries -join ' | '))`"," +
    "`"gateway4`":`"$(EscJ $gw4)`"," +
    "`"gateway6`":`"$(EscJ $gw6)`"," +
    "`"dns4`":`"$(EscJ $dns4)`"," +
    "`"dns6`":`"$(EscJ $dns6)`"," +
    "`"dnsSuffix`":`"$(EscJ $dnsSuffix)`"," +
    "`"winsPrimary`":`"$(EscJ $winsPrimary)`"," +
    "`"winsSecondary`":`"$(EscJ $winsSecond)`"," +
    "`"netbios`":`"$(EscJ $netbiosTxt)`"," +
    "`"dhcpv6Iaid`":`"$(EscJ $dhcpv6Iaid)`"," +
    "`"dhcpv6Duid`":`"$(EscJ $dhcpv6Duid)`"" +
    "}"
}
$ipJson    = "[`n" + ($ipJsonLines -join ",`n") + "`n]"
$globalJson = "{" + (($globalInfo.GetEnumerator() | ForEach-Object { "`"$(EscJ $_.Key)`":`"$(EscJ $_.Value)`"" }) -join ",") + "}"
Write-Host "Hostname : $hostname" -ForegroundColor Cyan
Write-Host "Windows  : $winFullVer" -ForegroundColor Cyan

# ================================================================
# 1. INSTALLED PROGRAMS
# ================================================================
$registryPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$installedPrograms = foreach ($path in $registryPaths) {
    if (Test-Path $path) {
        Get-ItemProperty $path |
            Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne "" } |
            Select-Object `
                @{Name="Name";        Expression={ [string]$_.DisplayName }},
                @{Name="Version";     Expression={ [string]$_.DisplayVersion }},
                @{Name="Publisher";   Expression={ [string]$_.Publisher }},
                @{Name="InstallDate"; Expression={
                    if ($_.InstallDate -match '^\d{8}$') {
                        [datetime]::ParseExact([string]$_.InstallDate,"yyyyMMdd",$null).ToString("MMMM d, yyyy")
                    } else { [string]$_.InstallDate }
                }},
                @{Name="Size_MB"; Expression={
                    if ($_.EstimatedSize) { [math]::Round($_.EstimatedSize/1024,1) } else { "" }
                }}
    }
}
$installedPrograms = $installedPrograms | Sort-Object Name -Unique
Write-Host "Found $($installedPrograms.Count) installed programs." -ForegroundColor Cyan
$installedPrograms | Export-Csv -Path $csvPrograms -NoTypeInformation -Encoding UTF8
Write-Host "Programs CSV: $csvPrograms" -ForegroundColor Green

# ================================================================
# 2. DEVICE DRIVERS
# ================================================================
Write-Host "Collecting drivers (may take a moment)..." -ForegroundColor Cyan
$drivers = Get-CimInstance -ClassName Win32_PnPSignedDriver |
    Where-Object { $_.DeviceName -and $_.DeviceName.Trim() -ne "" } |
    Select-Object `
        @{Name="DeviceName";     Expression={ [string]$_.DeviceName }},
        @{Name="DeviceClass";    Expression={ [string]$_.DeviceClass }},
        @{Name="Manufacturer";   Expression={ [string]$_.Manufacturer }},
        @{Name="DriverVersion";  Expression={ [string]$_.DriverVersion }},
        @{Name="DriverDate";     Expression={
            if ($_.DriverDate) { try { ([datetime]$_.DriverDate).ToString("MMMM d, yyyy") } catch { [string]$_.DriverDate } } else { "" }
        }},
        @{Name="DriverProvider"; Expression={ [string]$_.DriverProviderName }},
        @{Name="InfName";        Expression={ [string]$_.InfName }},
        @{Name="IsSigned";       Expression={ if ($_.IsSigned) { "Yes" } else { "No" } }},
        @{Name="Status";         Expression={
            switch ($_.ConfigManagerErrorCode) {
                0  { "OK" }          1  { "Error" }         2  { "Disabled" }
                3  { "Driver Error" } 10 { "Error" }         18 { "Needs Reinstall" }
                19 { "Registry Error" } 21 { "Will Be Removed" } 22 { "Disabled" }
                24 { "Not Present" } 28 { "No Drivers" }     29 { "Disabled - Firmware" }
                31 { "Not Working" } 32 { "Driver Load Failed" } 33 { "Resource Conflict" }
                34 { "IRQ Conflict" } 35 { "BIOS Conflict" } 43 { "Stopped - Error Reported" }
                default { if ($_.ConfigManagerErrorCode) { "Code $($_.ConfigManagerErrorCode)" } else { "OK" } }
            }
        }},
        @{Name="ErrorCode"; Expression={ [string]$_.ConfigManagerErrorCode }}
$drivers = $drivers | Sort-Object DeviceClass, DeviceName
Write-Host "Found $($drivers.Count) drivers." -ForegroundColor Cyan
$drivers | Export-Csv -Path $csvDrivers -NoTypeInformation -Encoding UTF8
Write-Host "Drivers CSV: $csvDrivers" -ForegroundColor Green

# ================================================================
# 3. EVENT LOGS - System + Application, last 48 hours, all levels
# ================================================================
# Prompt the user - default to N after 7 seconds
Write-Host ""
Write-Host "  Collect Event Viewer logs?" -ForegroundColor Yellow
Write-Host "  Logs collected: System, Application (last 48 hours, all severity levels)" -ForegroundColor DarkGray
Write-Host "  [Y/N] - defaulting to N in 7 seconds..." -ForegroundColor DarkGray
Write-Host ""

$collectEvents = $false
$deadline = (Get-Date).AddSeconds(7)
while ((Get-Date) -lt $deadline) {
    if ($Host.UI.RawUI.KeyAvailable) {
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character
        if ($key -match '^[Yy]$') { $collectEvents = $true;  break }
        if ($key -match '^[Nn]$') { $collectEvents = $false; break }
    }
    Start-Sleep -Milliseconds 100
}

$allEvents = @()
if ($collectEvents) {
    Write-Host "Collecting event logs (last 48 hours)..." -ForegroundColor Cyan
    $since      = (Get-Date).AddHours(-48)
    $logSources = @("System", "Application")

    # Level map: 1=Critical,2=Error,3=Warning,4=Information,5=Verbose
    $levelName = @{ 1="Critical"; 2="Error"; 3="Warning"; 4="Information"; 5="Verbose" }

    $allEvents = foreach ($log in $logSources) {
        try {
            Get-WinEvent -LogName $log -ErrorAction Stop |
                Where-Object { $_.TimeCreated -ge $since } |
                Select-Object `
                    @{Name="Log";       Expression={ $log }},
                    @{Name="TimeCreated"; Expression={ $_.TimeCreated.ToString("MMM d, yyyy h:mm:ss tt") }},
                    @{Name="Level";     Expression={ if ($levelName.ContainsKey([int]$_.Level)) { $levelName[[int]$_.Level] } else { [string]$_.Level } }},
                    @{Name="LevelNum";  Expression={ [int]$_.Level }},
                    @{Name="EventID";   Expression={ [string]$_.Id }},
                    @{Name="Source";    Expression={ [string]$_.ProviderName }},
                    @{Name="Message";   Expression={ ($_.Message -replace "`r`n"," " -replace "`n"," " -replace "`r"," ").Trim() }}
        } catch {
            Write-Warning "Could not read log '$log': $_"
        }
    }

    $allEvents = $allEvents | Sort-Object TimeCreated -Descending
    Write-Host "Collected $($allEvents.Count) events." -ForegroundColor Cyan
    $allEvents | Select-Object Log,TimeCreated,Level,EventID,Source,Message |
        Export-Csv -Path $csvEvents -NoTypeInformation -Encoding UTF8
    Write-Host "Events CSV: $csvEvents" -ForegroundColor Green
} else {
    Write-Host "Skipping event log collection." -ForegroundColor DarkGray
}


# ================================================================
# 3b. WINDOWS / KB UPDATES
# ================================================================
Write-Host "Collecting installed Windows updates..." -ForegroundColor Cyan

$winUpdates = @()

# Source 1: Get-HotFix (fast, covers most KBs)
try {
    $hotfixes = Get-HotFix | Select-Object `
        @{Name="KBNumber";       Expression={ [string]$_.HotFixID }},
        @{Name="Description";    Expression={ [string]$_.Description }},
        @{Name="InstalledOn";    Expression={
            if ($_.InstalledOn) {
                try { ([datetime]$_.InstalledOn).ToString("MMMM d, yyyy") } catch { [string]$_.InstalledOn }
            } else { "" }
        }},
        @{Name="InstalledBy";    Expression={ [string]$_.InstalledBy }},
        @{Name="Source";         Expression={ "HotFix/WMI" }}
    $winUpdates += $hotfixes
    Write-Host "  HotFix entries: $($hotfixes.Count)" -ForegroundColor Cyan
} catch {
    Write-Warning "Get-HotFix failed: $_"
}

# Source 2: Windows Update COM object (catches Feature Updates, Drivers via WU, etc.)
try {
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $histCount = $searcher.GetTotalHistoryCount()
    if ($histCount -gt 0) {
        $history = $searcher.QueryHistory(0, $histCount)
        $wuEntries = foreach ($item in $history) {
            if (-not $item.Title) { continue }
            # Extract KB number from title if present
            $kb = if ($item.Title -match 'KB(\d+)') { "KB$($Matches[1])" } else { "" }
            $resultCode = switch ($item.ResultCode) {
                1 { "In Progress" } 2 { "Succeeded" } 3 { "Succeeded (Reboot Required)" }
                4 { "Failed" } 5 { "Aborted" } default { "Unknown ($($item.ResultCode))" }
            }
            [PSCustomObject]@{
                KBNumber    = $kb
                Description = [string]$item.Title
                InstalledOn = if ($item.Date -and $item.Date -ne [datetime]::MinValue) { $item.Date.ToString("MMMM d, yyyy") } else { "" }
                InstalledBy = ""
                Source      = "Windows Update History"
            }
        }
        # Only add WU entries that have a KB and aren't already in hotfixes (avoid duplicates)
        $existingKBs = $winUpdates | Where-Object { $_.KBNumber } | Select-Object -ExpandProperty KBNumber
        foreach ($wu in $wuEntries) {
            if ($wu.KBNumber -and $existingKBs -contains $wu.KBNumber) { continue }
            $winUpdates += $wu
        }
        Write-Host "  Windows Update History entries added: $(($wuEntries | Measure-Object).Count)" -ForegroundColor Cyan
    }
} catch {
    Write-Warning "Windows Update COM query failed (may be normal): $_"
}

# Sort by install date descending
$winUpdates = $winUpdates | Sort-Object { 
    try { [datetime]::Parse($_.InstalledOn) } catch { [datetime]::MinValue }
} -Descending

Write-Host "Total update entries: $($winUpdates.Count)" -ForegroundColor Cyan
$winUpdates | Export-Csv -Path $csvUpdates -NoTypeInformation -Encoding UTF8
Write-Host "Updates CSV: $csvUpdates" -ForegroundColor Green

# ================================================================
# 3c. BATTERY REPORT (via powercfg /batteryreport)
# ================================================================
Write-Host "Generating battery report..." -ForegroundColor Cyan
$batteryHasBattery = $false
$batteryB64        = ""

try {
    $null = & powercfg /batteryreport /output $batteryReportPath 2>&1
    if (Test-Path $batteryReportPath) {
        $batteryHasBattery = $true
        # Parse design/full charge capacity out of the report HTML before encoding
        $rptRaw = Get-Content $batteryReportPath -Raw -ErrorAction SilentlyContinue
        if ($rptRaw) {
            # Actual structure: DESIGN CAPACITY</span></td><td>63,004 mWh
            $dMatch = [regex]::Match($rptRaw, 'DESIGN CAPACITY</span></td><td>([\d,]+)\s*mWh', 'IgnoreCase')
            $fMatch = [regex]::Match($rptRaw, 'FULL CHARGE CAPACITY</span></td><td>([\d,]+)\s*mWh', 'IgnoreCase')
            if ($dMatch.Success -and $fMatch.Success) {
                $script:rptDesignCap = [int]($dMatch.Groups[1].Value -replace ',','')
                $script:rptFullCap   = [int]($fMatch.Groups[1].Value -replace ',','')
                Write-Host "Battery capacity from report: Design=$($script:rptDesignCap) mWh  Full=$($script:rptFullCap) mWh" -ForegroundColor Cyan
            } else {
                Write-Host "Battery capacity regex did not match report HTML." -ForegroundColor DarkGray
            }
        }
        # Read and base64-encode so it embeds as a self-contained data URI in the iframe
        $batteryBytes = [System.IO.File]::ReadAllBytes($batteryReportPath)
        $batteryB64   = [Convert]::ToBase64String($batteryBytes)
        Remove-Item -Path $batteryReportPath -Force -ErrorAction SilentlyContinue
        Write-Host "Battery report encoded and removed: $batteryReportPath" -ForegroundColor Green
    }
} catch {
    Write-Warning "Battery report failed: $_"
}

# ================================================================
# 3d. BATTERY CAPACITY (Design vs Full Charge) - three-source waterfall
# ================================================================
$battDesignCap   = 0
$battFullCap     = 0
$battCapPct      = 0
$battCapStr      = ""

# Source 1: Values parsed from powercfg battery report (most reliable, already done above)
if ($script:rptDesignCap -gt 0 -and $script:rptFullCap -gt 0) {
    $battDesignCap = $script:rptDesignCap
    $battFullCap   = $script:rptFullCap
    Write-Host "Battery capacity source: powercfg report" -ForegroundColor Cyan
}

# Source 2: root\WMI BatteryStaticData + BatteryFullChargedCapacity (requires admin)
if ($battDesignCap -eq 0) {
    try {
        $batStatic = Get-CimInstance -Namespace "root\WMI" -ClassName "BatteryStaticData" -ErrorAction SilentlyContinue | Select-Object -First 1
        $batFull   = Get-CimInstance -Namespace "root\WMI" -ClassName "BatteryFullChargedCapacity" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($batStatic -and $batFull -and $batStatic.DesignedCapacity -gt 0) {
            $battDesignCap = [int]$batStatic.DesignedCapacity
            $battFullCap   = [int]$batFull.FullChargedCapacity
            Write-Host "Battery capacity source: root\WMI" -ForegroundColor Cyan
        }
    } catch { }
}

# Source 3: Win32_Battery DesignCapacity / FullChargeCapacity
if ($battDesignCap -eq 0) {
    try {
        $bat2 = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($bat2 -and $bat2.DesignCapacity -gt 0) {
            $battDesignCap = [int]$bat2.DesignCapacity
            $battFullCap   = if ($bat2.FullChargeCapacity -gt 0) { [int]$bat2.FullChargeCapacity } else { $battDesignCap }
            Write-Host "Battery capacity source: Win32_Battery" -ForegroundColor Cyan
        }
    } catch { }
}

if ($battDesignCap -gt 0 -and $battFullCap -gt 0) {
    $battCapPct = [math]::Round(($battFullCap / $battDesignCap) * 100, 1)
    $battCapStr = "$battCapPct% health ($([math]::Round($battFullCap/1000,1))/$([math]::Round($battDesignCap/1000,1)) Wh)"
    Write-Host "Battery health: $battCapStr" -ForegroundColor Cyan
} else {
    Write-Host "Battery capacity data unavailable from all sources." -ForegroundColor DarkGray
}

# ================================================================
# 3e. CURRENT BATTERY CHARGE LEVEL
# ================================================================
$battCurrentPct = 0
$battChargeStr  = ""
$battStatus     = ""
try {
    $batWmi = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($batWmi) {
        $battCurrentPct = [int]$batWmi.EstimatedChargeRemaining
        $battStatus     = switch ($batWmi.BatteryStatus) {
            1 { "Discharging" }  2 { "AC / Charging" }  3 { "Fully Charged" }
            4 { "Low" }          5 { "Critical" }         6 { "Charging+High" }
            7 { "Charging+Low" } 8 { "Charging+Critical"} 9 { "Undefined" }
            11{ "Partially Charged" } default { "" }
        }
    }
} catch { }

# ================================================================
# 4. BUILD HTML
# ================================================================
$generated    = Get-Date -Format "dddd, MMMM d yyyy 'at' h:mm tt"
$progCount    = $installedPrograms.Count
$driverCount  = $drivers.Count
$eventCount   = $allEvents.Count
$updateCount  = $winUpdates.Count
$problemCount = ($drivers | Where-Object { $_.Status -ne "OK" -and $_.Status -ne "Disabled" }).Count
$critErrCount = ($allEvents | Where-Object { $_.LevelNum -le 2 -and $_.LevelNum -ge 1 }).Count
$eventsSkipped = -not $collectEvents

function Enc($s) { [System.Web.HttpUtility]::HtmlEncode([string]$s) }

# Dell clickable serial (defined after Enc)
$serialDisplay = if ($isDell -and $hwSerial) {
    "<a href='https://www.dell.com/support/product-details/en-us/servicetag/$(Enc $hwSerial)/overview' target='_blank' style='color:var(--accent);text-decoration:underline;font-family:inherit'>$(Enc $hwSerial)</a>"
} else { Enc $hwSerial }

# -- Program rows --
$progRows = foreach ($p in $installedPrograms) {
    $size = if ($p.Size_MB) { $p.Size_MB } else { "" }
    "<tr><td>$(Enc $p.Name)</td><td>$(Enc $p.Version)</td><td>$(Enc $p.Publisher)</td><td>$(Enc $p.InstallDate)</td><td>$size</td></tr>"
}

# -- Driver rows --
$driverRows = foreach ($d in $drivers) {
    $sc = switch ($d.Status) { "OK" { "status-ok" } "Disabled" { "status-disabled" } default { "status-error" } }
    $sgn = if ($d.IsSigned -eq "Yes") { "signed-yes" } else { "signed-no" }
    "<tr><td>$(Enc $d.DeviceName)</td><td>$(Enc $d.DeviceClass)</td><td>$(Enc $d.Manufacturer)</td><td>$(Enc $d.DriverVersion)</td><td>$(Enc $d.DriverDate)</td><td>$(Enc $d.DriverProvider)</td><td><span class='$sgn'>$(Enc $d.IsSigned)</span></td><td>$(Enc $d.InfName)</td><td><span class='status-badge $sc'>$(Enc $d.Status)</span></td></tr>"
}

# -- Event rows --
$eventRows = foreach ($e in $allEvents) {
    $lvlClass = switch ($e.LevelNum) {
        1 { "lvl-critical" }
        2 { "lvl-error" }
        3 { "lvl-warning" }
        5 { "lvl-verbose" }
        default { "lvl-info" }
    }
    $fullMsgEnc = Enc $e.Message
    if ($e.Message.Length -gt 120) {
        $shortEnc = Enc $e.Message.Substring(0,120)
        $msgCell = "<td class='msg-cell'><span class='msg-short'>$shortEnc<span class='msg-ellipsis'>... </span><button class='msg-expand-btn' onclick='toggleMsg(this)'>more</button></span><span class='msg-full' style='display:none'>$fullMsgEnc<button class='msg-expand-btn' onclick='toggleMsg(this)'>less</button></span></td>"
    } else {
        $msgCell = "<td class='msg-cell'>$fullMsgEnc</td>"
    }
    "<tr data-log='$(Enc $e.Log)' data-level='$($e.LevelNum)'><td>$(Enc $e.TimeCreated)</td><td>$(Enc $e.Log)</td><td><span class='lvl-badge $lvlClass'>$(Enc $e.Level)</span></td><td class='evid'>$(Enc $e.EventID)</td><td>$(Enc $e.Source)</td>$msgCell</tr>"
}

$problemBadge  = if ($problemCount -gt 0)  { "<span class='badge badge-warn'>$problemCount driver issues</span>" } else { "" }
$critErrBadge  = if ($critErrCount -gt 0)  { "<span class='badge badge-danger'>$critErrCount crit/errors</span>" } else { "" }
$globalJsonEmbed = $globalJson

# ================================================================
# 4b. BASE64-ENCODE CSVs for embedded download links
# ================================================================
function GetCsvB64($path) {
    if (Test-Path $path) {
        $bytes = [System.IO.File]::ReadAllBytes($path)
        return [Convert]::ToBase64String($bytes)
    }
    return ""
}
$csvProgramsB64 = GetCsvB64 $csvPrograms
$csvDriversB64  = GetCsvB64 $csvDrivers
$csvEventsB64   = if ($collectEvents) { GetCsvB64 $csvEvents } else { "" }
$csvUpdatesB64  = GetCsvB64 $csvUpdates

# -- Update rows --
$updateRows = foreach ($u in $winUpdates) {
    $srcClass = switch ($u.Source) {
        "HotFix/WMI"              { "src-hotfix" }
        "Windows Update History"  { "src-wu" }
        default                   { "" }
    }
    "<tr><td class='upd-kb'>$(Enc $u.KBNumber)</td><td>$(Enc $u.Description)</td><td>$(Enc $u.InstalledOn)</td><td>$(Enc $u.InstalledBy)</td><td><span class='upd-src $srcClass'>$(Enc $u.Source)</span></td></tr>"
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>System Inventory - $hostname</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap" rel="stylesheet">
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  :root{
    --bg:#0f1117;--surface:#181c27;--surface2:#1e2436;--border:#2a2f3f;
    --accent:#4f9eff;--accent2:#00e5c3;--warn:#ffb340;--danger:#ff5f57;
    --verbose:#a78bfa;--text:#d4daf0;--muted:#606880;
    --row-hover:#1e2436;--row-alt:#161a28;
  }
  body{background:var(--bg);color:var(--text);font-family:'IBM Plex Sans',sans-serif;font-size:13px;min-height:100vh}

  /* Header */
  header{padding:28px 40px 22px;border-bottom:1px solid var(--border);display:grid;grid-template-columns:1fr auto;gap:16px;align-items:start}
  .header-title{font-family:'IBM Plex Mono',monospace;font-size:22px;font-weight:600;color:#fff;letter-spacing:-.5px}
  .header-title span{color:var(--accent)}
  .header-meta{margin-top:10px;display:flex;flex-direction:column;gap:4px}
  .meta-row{display:flex;align-items:baseline;gap:8px;font-family:'IBM Plex Mono',monospace;font-size:11px}
  .meta-label{color:var(--muted);min-width:88px}
  .meta-value{color:var(--text)}
  .meta-value.accent{color:var(--accent2)}
  .header-right{display:flex;flex-direction:column;align-items:flex-end;gap:10px}
  .header-badges{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}
  .badge-group{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
  .badge{font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:600;padding:4px 10px;border-radius:4px;white-space:nowrap}
  .badge-blue{background:var(--accent);color:#000}
  .badge-teal{background:var(--accent2);color:#000}
  .badge-warn{background:var(--warn);color:#000}
  .badge-danger{background:var(--danger);color:#fff}
  .badge-boot-ok{background:rgba(0,229,195,.15);border:1px solid var(--accent2);color:var(--accent2)}
  .badge-boot-warn{background:rgba(255,95,87,.18);border:1px solid var(--danger);color:var(--danger)}
  .badge-cap-warn{background:rgba(255,179,64,.15);border:1px solid var(--warn);color:var(--warn)}
  .badge-cap-low{background:rgba(255,95,87,.18);border:1px solid var(--danger);color:var(--danger)}
  .badge-purple{background:#7c3aed;color:#fff}

  /* Battery pill + popout */
  .bat-pill{display:inline-flex;align-items:center;gap:7px;font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:600;padding:4px 10px;border-radius:4px;white-space:nowrap;cursor:pointer;user-select:none;position:relative}
  .bat-pill:hover{filter:brightness(1.15)}
  .bat-icon{display:inline-flex;align-items:center}
  .bat-body{width:22px;height:10px;border-radius:2px;border:1.5px solid currentColor;position:relative;display:inline-block;vertical-align:middle}
  .bat-body::after{content:'';position:absolute;right:-4px;top:50%;transform:translateY(-50%);width:3px;height:5px;border-radius:0 1px 1px 0;background:currentColor}
  .bat-fill{position:absolute;left:1px;top:1px;bottom:1px;border-radius:1px}
  .bat-caret{font-size:9px;margin-left:2px;transition:transform .2s}
  .bat-pill.open .bat-caret{transform:rotate(90deg)}
  .bat-popout{
    display:none;position:absolute;top:calc(100% + 8px);right:0;
    background:var(--surface);border:1px solid var(--border2,var(--border));
    border-radius:8px;padding:14px 16px;min-width:220px;z-index:50;
    box-shadow:0 12px 32px rgba(0,0,0,.5);
    font-family:'IBM Plex Mono',monospace;font-size:11px;
  }
  .bat-pill.open .bat-popout{display:block}
  .bat-popout-row{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;gap:16px}
  .bat-popout-label{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.8px}
  .bat-popout-val{font-weight:600;font-size:12px}
  .bat-bar-wrap{height:7px;background:var(--border);border-radius:4px;overflow:hidden;margin-top:4px;margin-bottom:10px}
  .bat-bar-fill{height:100%;border-radius:4px;transition:width .4s ease}
  .bat-popout-status{color:var(--muted);font-size:10px;text-align:center;margin-top:2px}

  /* IP button */
  .ip-btn{font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:600;padding:6px 14px;border-radius:5px;border:1px solid var(--accent);background:rgba(79,158,255,.08);color:var(--accent);cursor:pointer;transition:all .15s;white-space:nowrap;display:flex;align-items:center;gap:6px}
  .ip-btn:hover{background:rgba(79,158,255,.18)}

  /* Modal */
  .modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:100;align-items:flex-start;justify-content:center;overflow-y:auto;padding:40px 20px;backdrop-filter:blur(4px)}
  .modal-overlay.open{display:flex}
  .modal{background:var(--surface);border:1px solid var(--border);border-radius:10px;width:720px;max-width:96vw;display:flex;flex-direction:column;box-shadow:0 24px 60px rgba(0,0,0,.6)}
  .modal-header{padding:18px 22px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
  .modal-header h2{font-family:'IBM Plex Mono',monospace;font-size:14px;font-weight:600;color:#fff}
  .modal-header h2 span{color:var(--accent)}
  .modal-close{background:none;border:none;color:var(--muted);font-size:20px;cursor:pointer;line-height:1;padding:2px 6px;border-radius:4px;transition:color .15s}
  .modal-close:hover{color:var(--text)}
  .modal-body{padding:18px 22px 24px;display:flex;flex-direction:column;gap:16px}
  .adapter-card{border:1px solid var(--border);border-radius:7px}
  .adapter-name{padding:9px 14px;background:var(--surface2);font-family:'IBM Plex Mono',monospace;font-size:12px;font-weight:600;color:var(--accent2);border-bottom:1px solid var(--border)}
  .adapter-fields{display:grid;grid-template-columns:180px 1fr}
  .collapsible-group{display:flex;flex-direction:column;gap:0}
  .collapse-btn{font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:600;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--muted);cursor:pointer;text-align:left;transition:all .15s;display:flex;align-items:center;gap:8px}
  .collapse-btn:hover{border-color:var(--accent);color:var(--text)}
  .collapse-arrow{font-size:9px;transition:transform .15s}
  .collapse-body{display:none;flex-direction:column;gap:12px;margin-top:8px}
  .field-label{padding:7px 14px;font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--muted);border-bottom:1px solid var(--border);border-right:1px solid var(--border)}
  .field-value{padding:7px 14px;font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--text);border-bottom:1px solid var(--border);word-break:break-all}
  .adapter-fields>div:nth-last-child(-n+2){border-bottom:none}

  /* Tabs */
  .tabs{display:flex;padding:0 40px;border-bottom:1px solid var(--border);background:var(--surface)}
  .tab-btn{font-family:'IBM Plex Mono',monospace;font-size:12px;font-weight:600;padding:14px 22px;background:none;border:none;border-bottom:2px solid transparent;color:var(--muted);cursor:pointer;transition:color .15s,border-color .15s;white-space:nowrap}
  .tab-btn:hover{color:var(--text)}
  .tab-btn.active{color:var(--accent);border-bottom-color:var(--accent)}

  /* Controls */
  .controls{padding:13px 40px;display:flex;align-items:center;gap:10px;border-bottom:1px solid var(--border);background:var(--surface);position:sticky;top:0;z-index:10;flex-wrap:wrap}
  .search-wrap{position:relative;flex:1;min-width:200px;max-width:380px}
  .search-wrap svg{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--muted);pointer-events:none}
  .search-wrap input{width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);font-family:'IBM Plex Mono',monospace;font-size:12px;padding:7px 10px 7px 32px;border-radius:5px;outline:none;transition:border-color .15s}
  .search-wrap input:focus{border-color:var(--accent)}
  .search-wrap input::placeholder{color:var(--muted)}
  .result-count{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--muted);white-space:nowrap;margin-left:auto}
  .dl-csv-btn{font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:600;padding:5px 11px;border-radius:4px;border:1px solid var(--border);background:var(--bg);color:var(--accent2);cursor:pointer;text-decoration:none;white-space:nowrap;transition:all .15s}
  .dl-csv-btn:hover{border-color:var(--accent2);background:rgba(0,229,195,.08)}
  .filter-btn{font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:600;padding:5px 11px;border-radius:4px;border:1px solid var(--border);background:var(--bg);color:var(--muted);cursor:pointer;transition:all .15s;white-space:nowrap}
  .filter-btn:hover{border-color:var(--warn);color:var(--warn)}
  .filter-btn.active{border-color:var(--warn);color:var(--warn);background:rgba(255,179,64,.08)}

  /* Level filter pills */
  .level-filters{display:flex;gap:6px;flex-wrap:wrap}
  .lvl-pill{font-family:'IBM Plex Mono',monospace;font-size:10px;font-weight:600;padding:4px 10px;border-radius:20px;border:1px solid var(--border);background:var(--bg);cursor:pointer;transition:all .15s;white-space:nowrap;color:var(--muted)}
  .lvl-pill.active-critical{border-color:var(--danger);color:var(--danger);background:rgba(255,95,87,.1)}
  .lvl-pill.active-error   {border-color:#ff8c69;color:#ff8c69;background:rgba(255,140,105,.1)}
  .lvl-pill.active-warning {border-color:var(--warn);color:var(--warn);background:rgba(255,179,64,.1)}
  .lvl-pill.active-information{border-color:var(--accent);color:var(--accent);background:rgba(79,158,255,.1)}
  .lvl-pill.active-verbose {border-color:var(--verbose);color:var(--verbose);background:rgba(167,139,250,.1)}

  /* Section / table */
  .section{display:none}
  .section.active{display:block}
  .table-wrap{overflow-x:auto;padding:0 40px 60px}
  table{width:100%;border-collapse:collapse;margin-top:18px;table-layout:auto}
  thead th{font-family:'IBM Plex Mono',monospace;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--accent);padding:10px 14px;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap;cursor:pointer;user-select:none}
  thead th:hover{color:var(--accent2)}
  thead th.sort-asc::after{content:" ^";font-size:9px}
  thead th.sort-desc::after{content:" v";font-size:9px}
  tbody tr{border-bottom:1px solid var(--border);transition:background .1s}
  tbody tr:nth-child(even){background:var(--row-alt)}
  tbody tr:hover{background:var(--row-hover)}
  td{padding:8px 14px;white-space:nowrap;max-width:340px;overflow:hidden;text-overflow:ellipsis;font-size:12px}
  td:first-child{color:#fff}

  #progTable td:nth-child(2){font-family:'IBM Plex Mono',monospace;color:var(--accent2);font-size:11px}
  #progTable td:nth-child(5){font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--muted);text-align:right}
  #drvTable  td:nth-child(4){font-family:'IBM Plex Mono',monospace;color:var(--accent2);font-size:11px}

  /* Event table */
  #evtTable td:nth-child(1){font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--muted);min-width:155px}
  .evid{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--accent2)}
  .msg-cell{max-width:500px;color:var(--muted);font-size:11px;white-space:normal;word-break:break-word}
  .msg-full{white-space:pre-wrap;word-break:break-word}
  .msg-expand-btn{font-family:'IBM Plex Mono',monospace;font-size:10px;font-weight:600;color:var(--accent);background:none;border:none;cursor:pointer;padding:0 2px;text-decoration:underline;vertical-align:baseline}
  .msg-expand-btn:hover{color:var(--accent2)}

  /* Status / level badges */
  .status-badge,.lvl-badge{font-family:'IBM Plex Mono',monospace;font-size:10px;font-weight:600;padding:2px 7px;border-radius:3px;display:inline-block;white-space:nowrap}
  .status-ok      {background:rgba(0,229,195,.15);color:var(--accent2)}
  .status-disabled{background:rgba(96,104,128,.25);color:var(--muted)}
  .status-error   {background:rgba(255,95,87,.15);color:var(--danger)}
  .signed-yes{color:var(--accent2);font-size:11px}
  .signed-no {color:var(--danger);font-size:11px}

  .lvl-critical   {background:rgba(255,95,87,.2);  color:var(--danger)}
  .lvl-error      {background:rgba(255,140,105,.15);color:#ff8c69}
  .lvl-warning    {background:rgba(255,179,64,.15); color:var(--warn)}
  .lvl-info       {background:rgba(79,158,255,.12); color:var(--accent)}
  .lvl-verbose    {background:rgba(167,139,250,.15);color:var(--verbose)}

  .no-results{text-align:center;padding:60px 0;color:var(--muted);font-family:'IBM Plex Mono',monospace;font-size:13px;display:none}

  /* Battery tab */
  .battery-wrap{padding:24px 40px 60px}
  .battery-no-bat{text-align:center;padding:80px 0;color:var(--muted);font-family:'IBM Plex Mono',monospace;font-size:14px}
  .battery-no-bat span{display:block;font-size:40px;margin-bottom:16px}
  .bat-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:24px}
  @media(max-width:900px){.bat-grid{grid-template-columns:1fr}}
  .bat-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;overflow:hidden}
  .bat-card-title{padding:11px 16px;font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--accent);border-bottom:1px solid var(--border);background:var(--surface2)}
  .bat-fields{display:grid;grid-template-columns:170px 1fr}
  .bat-label{padding:7px 14px;font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--muted);border-bottom:1px solid var(--border);border-right:1px solid var(--border)}
  .bat-value{padding:7px 14px;font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--text);border-bottom:1px solid var(--border);word-break:break-all}
  .bat-fields>div:nth-last-child(-n+2){border-bottom:none}
  .bat-health-bar-wrap{padding:14px 16px;border-top:1px solid var(--border)}
  .bat-health-label{font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);margin-bottom:6px;display:flex;justify-content:space-between}
  .bat-health-track{height:8px;background:var(--border);border-radius:4px;overflow:hidden}
  .bat-health-fill{height:100%;border-radius:4px;transition:width .4s ease}
  .bat-section-title{font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--accent);margin:24px 0 10px}
  .bat-table{width:100%;border-collapse:collapse;font-size:12px}
  .bat-table thead th{font-family:'IBM Plex Mono',monospace;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--accent);padding:9px 12px;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap;cursor:pointer;user-select:none}
  .bat-table thead th:hover{color:var(--accent2)}
  .bat-table tbody tr{border-bottom:1px solid var(--border)}
  .bat-table tbody tr:nth-child(even){background:var(--row-alt)}
  .bat-table tbody tr:hover{background:var(--row-hover)}
  .bat-table td{padding:7px 12px;white-space:nowrap;font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--muted)}
  .bat-table td:first-child{color:var(--text)}
  .state-ac{color:var(--accent2)}
  .state-dc{color:var(--warn)}

  /* Updates tab */
  #updTable td:nth-child(1){font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--accent2);font-weight:600}
  .upd-kb{min-width:110px}
  .upd-src{font-family:'IBM Plex Mono',monospace;font-size:10px;font-weight:600;padding:2px 7px;border-radius:3px;display:inline-block}
  .src-hotfix{background:rgba(79,158,255,.15);color:var(--accent)}
  .src-wu    {background:rgba(0,229,195,.12); color:var(--accent2)}
</style>
</head>
<body>

<!-- Header -->
<header>
  <div class="header-left">
    <div class="header-title">System <span>Inventory</span></div>
    <div class="header-meta">
      <div class="meta-row"><span class="meta-label">Host</span><span class="meta-value accent">$(Enc $hostname)</span></div>
      <div class="meta-row"><span class="meta-label">Manufacturer</span><span class="meta-value">$(Enc $hwMake)</span></div>
      <div class="meta-row"><span class="meta-label">Model</span><span class="meta-value">$(Enc $hwModel)</span></div>
      <div class="meta-row"><span class="meta-label">Serial</span><span class="meta-value">$serialDisplay</span></div>
      <div class="meta-row"><span class="meta-label">BIOS</span><span class="meta-value">$(Enc $biosDisplay)</span></div>
      <div class="meta-row"><span class="meta-label">Windows</span><span class="meta-value">$(Enc $winFullVer)</span></div>
      <div class="meta-row"><span class="meta-label">Installed</span><span class="meta-value">$(Enc $osInstallDate)</span></div>
      <div class="meta-row"><span class="meta-label">Generated</span><span class="meta-value">$generated</span></div>
    </div>
  </div>
  <div class="header-right">
    <div class="header-badges">
      <span class="badge $(if ($bootOld) { 'badge-boot-warn' } else { 'badge-boot-ok' })"> Boot: $lastBootStr ($uptimeStr)</span>
      $(if ($battCapStr) {
        $capColor = if ($battCapPct -ge 80) { 'badge-boot-ok' } elseif ($battCapPct -ge 50) { 'badge-cap-warn' } else { 'badge-cap-low' }
        "<span class='badge $capColor'> Bat: $battCapStr</span>"
      })
      <div class="badge-group" id="badges-programs">
        <span class="badge badge-blue">$progCount programs</span>
      </div>
      <div class="badge-group" id="badges-drivers" style="display:none">
        <span class="badge badge-teal">$driverCount drivers</span>
        $problemBadge
      </div>
      <div class="badge-group" id="badges-events" style="display:none">
        $(if ($eventsSkipped) { "<span class='badge' style='background:rgba(96,104,128,.3);color:var(--muted)'>Events not collected</span>" } else { "<span class='badge badge-purple'>$eventCount events</span>" })
        $critErrBadge
      </div>
      <div class="badge-group" id="badges-updates" style="display:none">
        <span class="badge badge-blue">$updateCount updates</span>
      </div>
      <div class="badge-group" id="badges-battery" style="display:none">
        $(if ($batteryHasBattery) {
          # Colours for the health bar
          if ($battCapPct -gt 0) {
            $hColor = if ($battCapPct -ge 80) { '#00e5c3' } elseif ($battCapPct -ge 50) { '#ffb340' } else { '#ff5f57' }
            $hBorder= if ($battCapPct -ge 80) { 'var(--accent2)' } elseif ($battCapPct -ge 50) { 'var(--warn)' } else { 'var(--danger)' }
            $hBg    = if ($battCapPct -ge 80) { 'rgba(0,229,195,.12)' } elseif ($battCapPct -ge 50) { 'rgba(255,179,64,.12)' } else { 'rgba(255,95,87,.12)' }
            $hPct   = [math]::Min($battCapPct,100)
          } else {
            $hColor = '#00e5c3'; $hBorder = 'var(--accent2)'; $hBg = 'rgba(0,229,195,.12)'; $hPct = 100
          }
          # Colours for the current charge bar
          $cColor = if ($battCurrentPct -ge 50) { '#00e5c3' } elseif ($battCurrentPct -ge 20) { '#ffb340' } else { '#ff5f57' }
          $cPct   = [math]::Min($battCurrentPct,100)
          # Health display strings
          $healthStr  = if ($battCapPct -gt 0) { "$battCapPct%" } else { "N/A" }
          $whStr      = if ($battCapPct -gt 0) { "$([math]::Round($battFullCap/1000,1)) / $([math]::Round($battDesignCap/1000,1)) Wh" } else { "" }
          $chargeStr  = if ($battCurrentPct -gt 0) { "$battCurrentPct%" } else { "N/A" }
          $statusStr  = if ($battStatus) { $battStatus } else { "" }

          # Pill outline + fill = charge color; health shown inside popout
          # Health bar only shown if we have real data
          $healthBarHtml = if ($battCapPct -gt 0) {
            "<div class='bat-bar-wrap'><div class='bat-bar-fill' style='width:$($hPct)%;background:$hColor'></div></div>"
          } else {
            "<div style='font-size:10px;color:var(--muted);padding:2px 0 6px'>Run as Administrator for health data</div>"
          }
          "<span class='bat-pill' style='background:$hBg;border:1px solid $cColor;color:$cColor' onclick='this.classList.toggle(""open"")'>" +
            "<span class='bat-icon'><span class='bat-body' style='border-color:$cColor'><span class='bat-fill' style='width:$($cPct)%;background:$cColor'></span></span></span>" +
            " $battCurrentPct% <span class='bat-caret'>&#9658;</span>" +
            "<div class='bat-popout' onclick='event.stopPropagation()'>" +
              "<div class='bat-popout-row'><span class='bat-popout-label'>Current Charge</span><span class='bat-popout-val' style='color:$cColor'>$chargeStr</span></div>" +
              "<div class='bat-bar-wrap'><div class='bat-bar-fill' style='width:$($cPct)%;background:$cColor'></div></div>" +
              "<div class='bat-popout-row'><span class='bat-popout-label'>Battery Health</span><span class='bat-popout-val' style='color:$hColor'>$healthStr</span></div>" +
              $healthBarHtml +
              "$(if ($whStr) { "<div class='bat-popout-row'><span class='bat-popout-label'>Capacity</span><span class='bat-popout-val' style='color:var(--muted2)'>$whStr</span></div>" })" +
              "$(if ($statusStr) { "<div class='bat-popout-status'>$statusStr</div>" })" +
            "</div>" +
          "</span>"
        } else {
          "<span class='badge' style='background:rgba(96,104,128,.3);color:var(--muted)'>No Battery</span>"
        })
      </div>
    </div>
    <button class="ip-btn" onclick="document.getElementById('ipModal').classList.add('open')">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
      IP Config
    </button>
  </div>
</header>

<!-- IP Modal -->
<div class="modal-overlay" id="ipModal" onclick="if(event.target===this)this.classList.remove('open')">
  <div class="modal">
    <div class="modal-header">
      <h2>Network <span>IP Configuration</span></h2>
      <button class="modal-close" onclick="document.getElementById('ipModal').classList.remove('open')">X</button>
    </div>
    <div class="modal-body" id="ipModalBody"></div>
  </div>
</div>

<!-- Tabs -->
<div class="tabs">
  <button class="tab-btn active" onclick="switchTab('programs',this)">Installed Programs</button>
  <button class="tab-btn"        onclick="switchTab('drivers', this)">Device Drivers</button>
  <button class="tab-btn"        onclick="switchTab('updates', this)">Windows Updates</button>
  <button class="tab-btn"        onclick="switchTab('events',  this)">Event Logs</button>
  <button class="tab-btn"        onclick="switchTab('battery', this)">Battery Report</button>
</div>

<!-- Programs -->
<div id="programs" class="section active">
  <div class="controls">
    <div class="search-wrap">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      <input type="text" id="progSearch" placeholder="Search programs, publishers..." oninput="filterPrograms()">
    </div>
    <span class="result-count" id="progCount">$progCount programs</span>
    $(if ($csvProgramsB64) { "<a class='dl-csv-btn' href='data:text/csv;base64,$csvProgramsB64' download='InstalledPrograms.csv'>&#8595; CSV</a>" })
  </div>
  <div class="table-wrap">
    <table id="progTable">
      <thead><tr>
        <th onclick="sortTable('progBody',0,this)">Name</th>
        <th onclick="sortTable('progBody',1,this)">Version</th>
        <th onclick="sortTable('progBody',2,this)">Publisher</th>
        <th onclick="sortTable('progBody',3,this)">Install Date</th>
        <th onclick="sortTable('progBody',4,this)">Size (MB)</th>
      </tr></thead>
      <tbody id="progBody">$($progRows -join "")</tbody>
    </table>
    <div class="no-results" id="progNoResults">No programs match your search.</div>
  </div>
</div>

<!-- Drivers -->
<div id="drivers" class="section">
  <div class="controls">
    <div class="search-wrap">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      <input type="text" id="drvSearch" placeholder="Search devices, drivers, manufacturers..." oninput="filterDrivers()">
    </div>
    <button class="filter-btn" id="issuesBtn" onclick="toggleIssues()">(!) Issues Only</button>
    <span class="result-count" id="drvCount">$driverCount drivers</span>
    $(if ($csvDriversB64) { "<a class='dl-csv-btn' href='data:text/csv;base64,$csvDriversB64' download='SystemDrivers.csv'>&#8595; CSV</a>" })
  </div>
  <div class="table-wrap">
    <table id="drvTable">
      <thead><tr>
        <th onclick="sortTable('drvBody',0,this)">Device Name</th>
        <th onclick="sortTable('drvBody',1,this)">Class</th>
        <th onclick="sortTable('drvBody',2,this)">Manufacturer</th>
        <th onclick="sortTable('drvBody',3,this)">Driver Version</th>
        <th onclick="sortTable('drvBody',4,this)">Driver Date</th>
        <th onclick="sortTable('drvBody',5,this)">Provider</th>
        <th onclick="sortTable('drvBody',6,this)">Signed</th>
        <th onclick="sortTable('drvBody',7,this)">INF File</th>
        <th onclick="sortTable('drvBody',8,this)">Status</th>
      </tr></thead>
      <tbody id="drvBody">$($driverRows -join "")</tbody>
    </table>
    <div class="no-results" id="drvNoResults">No drivers match your search.</div>
  </div>
</div>

<!-- Events -->
<div id="events" class="section">
  <div class="controls">
    <div class="search-wrap">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      <input type="text" id="evtSearch" placeholder="Search source, message, Event ID..." oninput="filterEvents()">
    </div>
    <!-- Log source filter -->
    <select id="logFilter" onchange="filterEvents()" style="font-family:'IBM Plex Mono',monospace;font-size:11px;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:5px;outline:none;cursor:pointer">
      <option value="">All Logs</option>
      <option value="System">System</option>
      <option value="Application">Application</option>
    </select>
    <!-- Level pills -->
    <div class="level-filters" id="levelFilters">
      <span class="lvl-pill" data-level="1" onclick="toggleLvl(this,'critical')">Critical</span>
      <span class="lvl-pill" data-level="2" onclick="toggleLvl(this,'error')">Error</span>
      <span class="lvl-pill" data-level="3" onclick="toggleLvl(this,'warning')">Warning</span>
      <span class="lvl-pill" data-level="4" onclick="toggleLvl(this,'information')">Info</span>
      <span class="lvl-pill" data-level="5" onclick="toggleLvl(this,'verbose')">Verbose</span>
    </div>
    <span class="result-count" id="evtCount">$eventCount events</span>
    $(if ($csvEventsB64) { "<a class='dl-csv-btn' href='data:text/csv;base64,$csvEventsB64' download='EventLogs.csv'>&#8595; CSV</a>" })
  </div>
  <div class="table-wrap">
    <table id="evtTable">
      <thead><tr>
        <th onclick="sortTable('evtBody',0,this)">Time</th>
        <th onclick="sortTable('evtBody',1,this)">Log</th>
        <th onclick="sortTable('evtBody',2,this)">Level</th>
        <th onclick="sortTable('evtBody',3,this)">Event ID</th>
        <th onclick="sortTable('evtBody',4,this)">Source</th>
        <th>Message</th>
      </tr></thead>
      <tbody id="evtBody">$($eventRows -join "")</tbody>
    </table>
    <div class="no-results" id="evtNoResults">No events match your filters.</div>
  </div>
  $(if ($eventsSkipped) { "<div style='text-align:center;padding:60px 0;color:var(--muted);font-family:IBM Plex Mono,monospace;font-size:13px'>Event log collection was skipped.<br><span style='font-size:11px;margin-top:8px;display:block'>Re-run the script and press Y when prompted.</span></div>" })
</div>

<!-- Updates -->
<div id="updates" class="section">
  <div class="controls">
    <div class="search-wrap">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      <input type="text" id="updSearch" placeholder="Search KB number, description..." oninput="filterUpdates()">
    </div>
    <span class="result-count" id="updCount">$updateCount updates</span>
    $(if ($csvUpdatesB64) { "<a class='dl-csv-btn' href='data:text/csv;base64,$csvUpdatesB64' download='WindowsUpdates.csv'>&#8595; CSV</a>" })
  </div>
  <div class="table-wrap">
    <table id="updTable">
      <thead><tr>
        <th onclick="sortTable('updBody',0,this)">KB Number</th>
        <th onclick="sortTable('updBody',1,this)">Description / Title</th>
        <th onclick="sortTable('updBody',2,this)">Installed On</th>
        <th onclick="sortTable('updBody',3,this)">Installed By</th>
        <th onclick="sortTable('updBody',4,this)">Source</th>
      </tr></thead>
      <tbody id="updBody">$($updateRows -join "")</tbody>
    </table>
    <div class="no-results" id="updNoResults">No updates match your search.</div>
  </div>
</div>

<!-- Battery Section -->
<div id="battery" class="section">
  <div id="batteryContent"></div>
</div>

<script>
// -- IP Modal --
const ipData      = $ipJson;
const globalCfg   = $globalJsonEmbed;
const batteryReportAvailable = "$(if ($batteryHasBattery) { 'true' } else { 'false' })";
const batteryB64  = "$batteryB64";

// -- Battery Tab --
(function(){
  const wrap = document.getElementById('batteryContent');
  if(batteryReportAvailable !== 'true'){
    wrap.innerHTML = '<div style="text-align:center;padding:80px 0;color:var(--muted);font-family:IBM Plex Mono,monospace;font-size:14px"><span style="display:block;font-size:40px;margin-bottom:16px"></span>No battery detected on this system.<br><span style="font-size:12px;margin-top:8px;display:block">Run as Administrator for best results.</span></div>';
    return;
  }
  const dlBtn = document.createElement('a');
  dlBtn.href     = 'data:text/html;base64,' + batteryB64;
  dlBtn.download = 'battery-report.html';
  dlBtn.className = 'dl-csv-btn';
  dlBtn.innerHTML = '&#8595; Download Battery Report';
  dlBtn.style.cssText = 'display:inline-block;margin:14px 0 0 40px';
  wrap.appendChild(dlBtn);

  const iframe = document.createElement('iframe');
  iframe.src   = 'data:text/html;base64,' + batteryB64;
  iframe.style.cssText = 'width:100%;height:calc(100vh - 200px);border:none;background:#fff;display:block;margin-top:10px';
  wrap.appendChild(iframe);
})();

(function(){
  const body = document.getElementById('ipModalBody');

  // Global section
  const globalFields = [
    ['Host Name',             globalCfg['Host Name']],
    ['Primary DNS Suffix',    globalCfg['Primary DNS Suffix']],
    ['Node Type',             globalCfg['Node Type']],
    ['IP Routing Enabled',    globalCfg['IP Routing Enabled'] === '1' ? 'Yes' : 'No'],
    ['WINS Proxy Enabled',    globalCfg['WINS Proxy Enabled']],
    ['DNS Suffix Search List',globalCfg['DNS Suffix Search List']],
  ].filter(([,v])=>v);

  if(globalFields.length){
    body.insertAdjacentHTML('beforeend',
      '<div class="adapter-card"><div class="adapter-name" style="color:var(--accent)">Global Settings</div>' +
      '<div class="adapter-fields">' +
      globalFields.map(([k,v])=>'<div class="field-label">'+k+'</div><div class="field-value">'+v+'</div>').join('') +
      '</div></div>'
    );
  }

  if(!ipData.length){
    body.insertAdjacentHTML('beforeend','<p style="color:var(--muted);font-family:IBM Plex Mono,monospace;font-size:12px;margin-top:12px">No adapters found.</p>');
    return;
  }

  function buildFields(a){
    return [
      ['Description',        a.description],
      ['Interface Type',     a.type],
      ['Status',             a.status],
      ['MAC Address',        a.mac],
      ['Link Speed',         a.speed],
      ['MTU',                a.mtu],
      ['DHCP Enabled',       a.dhcp],
      ['DHCP Server',        a.dhcpServer],
      ['Lease Obtained',     a.dhcpLeaseObtained],
      ['Lease Expires',      a.dhcpLeaseExpires],
      ['IPv4 Address(es)',   a.ipv4],
      ['IPv6 Address(es)',   a.ipv6],
      ['Default Gateway',    a.gateway4],
      ['IPv6 Gateway',       a.gateway6],
      ['DNS Servers (v4)',   a.dns4],
      ['DNS Servers (v6)',   a.dns6],
      ['DNS Suffix',         a.dnsSuffix],
      ['WINS Primary',       a.winsPrimary],
      ['WINS Secondary',     a.winsSecondary],
      ['NetBIOS over TCP/IP',a.netbios],
      ['DHCPv6 IAID',        a.dhcpv6Iaid],
      ['DHCPv6 Client DUID', a.dhcpv6Duid],
    ].filter(([,v])=>v && v.trim() !== '');
  }

  function buildCard(a){
    const hasIp  = (a.ipv4 && a.ipv4.trim()) || (a.ipv6 && a.ipv6.trim());
    const color  = hasIp ? 'var(--accent2)' : 'var(--muted)';
    const rows   = buildFields(a);
    const fieldsHtml = '<div class="adapter-fields">' +
      rows.map(([k,v])=>'<div class="field-label">'+k+'</div><div class="field-value">'+v+'</div>').join('') +
      '</div>';
    return '<div class="adapter-card">' +
      '<div class="adapter-name" style="color:'+color+'">'+a.name+
      ' <span style="font-weight:400;color:var(--muted);font-size:10px">['+a.status+']</span></div>'+
      fieldsHtml+'</div>';
  }

  // Split into active (has IP) and inactive
  const active   = ipData.filter(a => (a.ipv4 && a.ipv4.trim()) || (a.ipv6 && a.ipv6.trim()));
  const inactive = ipData.filter(a => !((a.ipv4 && a.ipv4.trim()) || (a.ipv6 && a.ipv6.trim())));

  active.forEach(a => body.insertAdjacentHTML('beforeend', buildCard(a)));

  if(inactive.length){
    const uid = 'inactive-adapters';
    body.insertAdjacentHTML('beforeend',
      '<div class="collapsible-group">' +
        '<button class="collapse-btn" onclick="toggleCollapse(\''+uid+'\')" id="btn-'+uid+'">' +
          '<span class="collapse-arrow">></span>' +
          'Other Adapters (no IP assigned) - '+inactive.length+
        '</button>' +
        '<div class="collapse-body" id="'+uid+'">'+
          inactive.map(a=>buildCard(a)).join('')+
        '</div>'+
      '</div>'
    );
  }
})();

function toggleCollapse(id){
  const el  = document.getElementById(id);
  const btn = document.getElementById('btn-'+id);
  const arrow = btn.querySelector('.collapse-arrow');
  const open = el.style.display !== 'none' && el.style.display !== '';
  if(open){ el.style.display='none'; arrow.textContent='>'; }
  else    { el.style.display='flex'; arrow.textContent='v'; }
}

// -- Tab switching --
function switchTab(id,btn){
  document.querySelectorAll('.section').forEach(s=>s.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  btn.classList.add('active');
  // Show only the badge group matching the active tab
  document.querySelectorAll('.badge-group').forEach(g=>g.style.display='none');
  const bg = document.getElementById('badges-'+id);
  if(bg) bg.style.display='flex';
}

// -- Updates filter --
function filterUpdates(){
  const q=document.getElementById('updSearch').value.toLowerCase();
  const rows=Array.from(document.getElementById('updBody').querySelectorAll('tr'));
  let v=0;
  rows.forEach(r=>{const show=r.textContent.toLowerCase().includes(q);r.style.display=show?'':'none';if(show)v++;});
  document.getElementById('updNoResults').style.display=v===0?'block':'none';
  document.getElementById('updCount').textContent=v===rows.length?rows.length+' updates':v+' of '+rows.length+' updates';
}

// -- Programs filter --
function filterPrograms(){
  const q=document.getElementById('progSearch').value.toLowerCase();
  const rows=Array.from(document.getElementById('progBody').querySelectorAll('tr'));
  let v=0;
  rows.forEach(r=>{const show=r.textContent.toLowerCase().includes(q);r.style.display=show?'':'none';if(show)v++;});
  document.getElementById('progNoResults').style.display=v===0?'block':'none';
  document.getElementById('progCount').textContent=v===rows.length?rows.length+' programs':v+' of '+rows.length+' programs';
}

// -- Drivers filter --
let issuesOnly=false;
function filterDrivers(){
  const q=document.getElementById('drvSearch').value.toLowerCase();
  const rows=Array.from(document.getElementById('drvBody').querySelectorAll('tr'));
  let v=0;
  rows.forEach(r=>{
    const tm=r.textContent.toLowerCase().includes(q);
    const im=!issuesOnly||!r.querySelector('.status-ok,.status-disabled');
    const show=tm&&im;r.style.display=show?'':'none';if(show)v++;
  });
  document.getElementById('drvNoResults').style.display=v===0?'block':'none';
  document.getElementById('drvCount').textContent=v===rows.length?rows.length+' drivers':v+' of '+rows.length+' drivers';
}
function toggleIssues(){issuesOnly=!issuesOnly;document.getElementById('issuesBtn').classList.toggle('active',issuesOnly);filterDrivers();}

// -- Events filter --
const activeLevels=new Set();
function toggleLvl(el,cls){
  const lv=parseInt(el.dataset.level);
  if(activeLevels.has(lv)){activeLevels.delete(lv);el.className='lvl-pill';}
  else{activeLevels.add(lv);el.className='lvl-pill active-'+cls;}
  filterEvents();
}
function filterEvents(){
  const q   =document.getElementById('evtSearch').value.toLowerCase();
  const log =document.getElementById('logFilter').value;
  const rows=Array.from(document.getElementById('evtBody').querySelectorAll('tr'));
  let v=0;
  rows.forEach(r=>{
    const textOk =r.textContent.toLowerCase().includes(q);
    const logOk  =!log||r.dataset.log===log;
    const lvlNum =parseInt(r.dataset.level);
    const lvlOk  =activeLevels.size===0||activeLevels.has(lvlNum);
    const show   =textOk&&logOk&&lvlOk;
    r.style.display=show?'':'none';if(show)v++;
  });
  document.getElementById('evtNoResults').style.display=v===0?'block':'none';
  document.getElementById('evtCount').textContent=v===rows.length?rows.length+' events':v+' of '+rows.length+' events';
}

// -- Sort --
const sortState={};
function sortTable(bodyId,col,th){
  const key=bodyId+col;sortState[key]=!sortState[key];const asc=sortState[key];
  th.closest('thead').querySelectorAll('th').forEach(h=>h.classList.remove('sort-asc','sort-desc'));
  th.classList.add(asc?'sort-asc':'sort-desc');
  const body=document.getElementById(bodyId);
  const rows=Array.from(body.querySelectorAll('tr'));
  rows.sort((a,b)=>{
    let av=a.cells[col]?.textContent.trim()||'';
    let bv=b.cells[col]?.textContent.trim()||'';
    const an=parseFloat(av),bn=parseFloat(bv);
    if(!isNaN(an)&&!isNaN(bn))return asc?an-bn:bn-an;
    return asc?av.localeCompare(bv):bv.localeCompare(av);
  });
  rows.forEach(r=>body.appendChild(r));
}

document.addEventListener('keydown',e=>{if(e.key==='Escape')document.getElementById('ipModal').classList.remove('open');});

// Close battery popout when clicking outside it
document.addEventListener('click', function(e){
  const pill = document.querySelector('.bat-pill.open');
  if(pill && !pill.contains(e.target)) pill.classList.remove('open');
});

function toggleMsg(btn){
  const cell = btn.closest('.msg-cell');
  const shortSpan = cell.querySelector('.msg-short');
  const fullSpan  = cell.querySelector('.msg-full');
  if(!shortSpan||!fullSpan) return;
  const isShowing = fullSpan.style.display !== 'none';
  shortSpan.style.display = isShowing ? '' : 'none';
  fullSpan.style.display  = isShowing ? 'none' : '';
}
</script>
</body>
</html>
"@

$html | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Host "`nHTML written: $htmlPath" -ForegroundColor Green

# ================================================================
# ZIP THE HTML - Maximum compression, same base name as HTML
# ================================================================
$zipPath = [System.IO.Path]::ChangeExtension($htmlPath, ".zip")
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    Add-Type -AssemblyName System.IO.Compression

    # Remove existing zip if re-running
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

    $zipStream  = [System.IO.File]::Open($zipPath, [System.IO.FileMode]::Create)
    $archive    = New-Object System.IO.Compression.ZipArchive($zipStream, [System.IO.Compression.ZipArchiveMode]::Create)
    $entryName  = [System.IO.Path]::GetFileName($htmlPath)
    $entry      = $archive.CreateEntry($entryName, [System.IO.Compression.CompressionLevel]::Optimal)
    $entryStream = $entry.Open()
    $htmlStream  = [System.IO.File]::OpenRead($htmlPath)
    $htmlStream.CopyTo($entryStream)
    $htmlStream.Close()
    $entryStream.Close()
    $archive.Dispose()
    $zipStream.Close()

    Write-Host "ZIP saved  : $zipPath" -ForegroundColor Green

    # Remove the loose HTML now that it is inside the zip
    Remove-Item -Path $htmlPath -Force -ErrorAction SilentlyContinue
    Write-Host "Loose HTML removed - zip is the keeper." -ForegroundColor Green
} catch {
    Write-Warning "ZIP creation failed: $_ -- HTML left in place."
}

# ================================================================
# CLEAN UP INTERMEDIATE TEMP FOLDER
# ================================================================
try {
    Remove-Item -Path $outputPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Temp files cleaned up." -ForegroundColor Green
} catch {
    Write-Warning "Temp cleanup failed: $_"
}

# ================================================================
# EXTRACT HTML TO A FRESH TEMP LOCATION AND OPEN IT
# (Keeps the real save path hidden from the browser's title bar)
# ================================================================
try {
    $previewDir  = Join-Path $env:TEMP ("SysInfoPreview_" + [System.Guid]::NewGuid().ToString("N").Substring(0,8))
    New-Item -ItemType Directory -Path $previewDir -Force | Out-Null

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $previewDir)

    $htmlPreview = Join-Path $previewDir ([System.IO.Path]::GetFileNameWithoutExtension($zipPath) + ".html")
    if (Test-Path $htmlPreview) {
        Start-Process $htmlPreview
        Write-Host "Opened from temp: $htmlPreview" -ForegroundColor Green
    } else {
        # Fallback: open whatever HTML landed in the preview dir
        $anyHtml = Get-ChildItem $previewDir -Filter "*.html" | Select-Object -First 1
        if ($anyHtml) { Start-Process $anyHtml.FullName }
    }
} catch {
    Write-Warning "Preview extraction failed: $_"
}

Write-Host "`nDone! Press any key to exit..." -ForegroundColor Green
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
