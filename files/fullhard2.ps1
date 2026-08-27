#requires -RunAsAdministrator
#requires -Version 5.1

<#
.SYNOPSIS
    FullHard - Windows Server 2022 Security Audit + Hardening

.DESCRIPTION
    Conservative security hardening profile for Windows Server 2022
    intended for gaming, web browsing and general desktop usage.

    Workflow:
      1. Pre-audit
      2. Backup
      3. Hardening
      4. Post-audit
      5. Reports

    Design principles:
      - IPv6 is NOT disabled
      - No global outbound firewall block
      - No forced DoH
      - No mass disabling of Windows services
      - RDP is disabled by default
      - SMBv1 is disabled when available
      - LLMNR is disabled
      - TLS 1.0/1.1 are disabled
      - PowerShell v2 is disabled when installed
      - Defender protection is strengthened
      - ASR is Audit mode by default
      - ASR Block mode requires -EnableASRBlock
      - Backup is created before changes
#>

[CmdletBinding()]
param(
    [switch]$AuditOnly,
    [switch]$ApplyHardening,
    [switch]$EnableRDP,
    [switch]$DisableNetworkDiscovery,
    [switch]$EnableASRBlock
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ============================================================
# GLOBALS
# ============================================================

$TimeStamp = Get-Date -Format "yyyyMMdd-HHmmss"

$RootPath   = Join-Path $env:ProgramData "FullHard"
$BackupPath = Join-Path $RootPath "Backup-$TimeStamp"
$ReportPath = Join-Path $RootPath "Reports-$TimeStamp"

New-Item -ItemType Directory -Path $RootPath   -Force | Out-Null
New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null

$LogFile    = Join-Path $ReportPath "FullHard-$TimeStamp.log"
$BeforeCsv  = Join-Path $ReportPath "Audit-Before.csv"
$AfterCsv   = Join-Path $ReportPath "Audit-After.csv"
$BeforeTxt  = Join-Path $ReportPath "Audit-Before.txt"
$AfterTxt   = Join-Path $ReportPath "Audit-After.txt"

$AuditResults = New-Object System.Collections.Generic.List[object]

# ============================================================
# LOGGING
# ============================================================

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("INFO","OK","WARN","ERROR")]
        [string]$Level = "INFO"
    )

    $Line = "{0} [{1}] {2}" -f `
        (Get-Date -Format "yyyy-MM-dd HH:mm:ss"),
        $Level,
        $Message

    try {
        Add-Content `
            -Path $LogFile `
            -Value $Line `
            -Encoding UTF8 `
            -ErrorAction SilentlyContinue
    }
    catch {
        # Logging failure must never terminate hardening.
    }

    switch ($Level) {
        "INFO"  { Write-Host $Line -ForegroundColor Cyan }
        "OK"    { Write-Host $Line -ForegroundColor Green }
        "WARN"  { Write-Host $Line -ForegroundColor Yellow }
        "ERROR" { Write-Host $Line -ForegroundColor Red }
    }
}

function Add-AuditResult {
    param(
        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [string]$Name,

        [ValidateSet("OK","WARN","FAIL","INFO")]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Details
    )

    $AuditResults.Add(
        [PSCustomObject]@{
            Category = $Category
            Name     = $Name
            Status   = $Status
            Details  = $Details
        }
    )

    $Color = switch ($Status) {
        "OK"   { "Green" }
        "WARN" { "Yellow" }
        "FAIL" { "Red" }
        "INFO" { "Cyan" }
    }

    Write-Host `
        ("[{0}] {1}: {2}" -f $Status, $Name, $Details) `
        -ForegroundColor $Color
}

# ============================================================
# HELPER - COMMAND EXISTS
# ============================================================

function Test-CommandAvailable {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

# ============================================================
# SYSTEM INFORMATION
# ============================================================

function Get-SystemInformation {

    Write-Log "Collecting system information..."

    try {
        $OS = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $CS = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop

        Add-AuditResult `
            -Category "System" `
            -Name "Operating System" `
            -Status "INFO" `
            -Details "$($OS.Caption) | Build $($OS.BuildNumber)"

        Add-AuditResult `
            -Category "System" `
            -Name "Computer" `
            -Status "INFO" `
            -Details "$($CS.Manufacturer) $($CS.Model)"

        Add-AuditResult `
            -Category "System" `
            -Name "Architecture" `
            -Status "INFO" `
            -Details "$($OS.OSArchitecture)"

        Add-AuditResult `
            -Category "System" `
            -Name "PowerShell" `
            -Status "INFO" `
            -Details $PSVersionTable.PSVersion.ToString()
    }
    catch {
        Add-AuditResult `
            -Category "System" `
            -Name "System information" `
            -Status "FAIL" `
            -Details $_.Exception.Message
    }
}

# ============================================================
# FIREWALL AUDIT
# ============================================================

function Test-Firewall {

    Write-Log "Auditing Windows Firewall..."

    if (-not (Test-CommandAvailable "Get-NetFirewallProfile")) {
        Add-AuditResult `
            -Category "Firewall" `
            -Name "Firewall audit" `
            -Status "FAIL" `
            -Details "Get-NetFirewallProfile is unavailable"

        return
    }

    try {
        $Profiles = @(Get-NetFirewallProfile -ErrorAction Stop)

        foreach ($Profile in $Profiles) {

            if ($Profile.Enabled) {
                Add-AuditResult `
                    -Category "Firewall" `
                    -Name "$($Profile.Name) firewall" `
                    -Status "OK" `
                    -Details "Enabled"
            }
            else {
                Add-AuditResult `
                    -Category "Firewall" `
                    -Name "$($Profile.Name) firewall" `
                    -Status "FAIL" `
                    -Details "Disabled"
            }

            if ($Profile.DefaultInboundAction -eq "Block") {
                Add-AuditResult `
                    -Category "Firewall" `
                    -Name "$($Profile.Name) inbound policy" `
                    -Status "OK" `
                    -Details "Block"
            }
            else {
                Add-AuditResult `
                    -Category "Firewall" `
                    -Name "$($Profile.Name) inbound policy" `
                    -Status "WARN" `
                    -Details "$($Profile.DefaultInboundAction)"
            }

            if ($Profile.DefaultOutboundAction -eq "Allow") {
                Add-AuditResult `
                    -Category "Firewall" `
                    -Name "$($Profile.Name) outbound policy" `
                    -Status "OK" `
                    -Details "Allow"
            }
            else {
                Add-AuditResult `
                    -Category "Firewall" `
                    -Name "$($Profile.Name) outbound policy" `
                    -Status "WARN" `
                    -Details "$($Profile.DefaultOutboundAction)"
            }
        }
    }
    catch {
        Add-AuditResult `
            -Category "Firewall" `
            -Name "Firewall audit" `
            -Status "FAIL" `
            -Details $_.Exception.Message
    }
}

# ============================================================
# LISTENING TCP PORTS
# ============================================================

function Test-ListeningPorts {

    Write-Log "Auditing listening TCP ports..."

    if (-not (Test-CommandAvailable "Get-NetTCPConnection")) {
        Add-AuditResult `
            -Category "Network" `
            -Name "Listening TCP ports" `
            -Status "WARN" `
            -Details "Get-NetTCPConnection unavailable"

        return
    }

    try {
        $Connections = @(
            Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Sort-Object LocalPort |
            Select-Object -Unique LocalAddress, LocalPort, OwningProcess
        )

        if ($Connections.Count -eq 0) {

            Add-AuditResult `
                -Category "Network" `
                -Name "Listening TCP ports" `
                -Status "OK" `
                -Details "None detected"

            return
        }

        Add-AuditResult `
            -Category "Network" `
            -Name "Listening TCP ports" `
            -Status "INFO" `
            -Details "$($Connections.Count) listening sockets"

        foreach ($Connection in $Connections) {

            try {
                $Process = Get-Process `
                    -Id $Connection.OwningProcess `
                    -ErrorAction Stop

                $ProcessName = $Process.ProcessName
            }
            catch {
                $ProcessName = "PID-$($Connection.OwningProcess)"
            }

            Add-AuditResult `
                -Category "Network" `
                -Name "TCP $($Connection.LocalPort)" `
                -Status "INFO" `
                -Details "$($Connection.LocalAddress) -> $ProcessName"
        }
    }
    catch {
        Add-AuditResult `
            -Category "Network" `
            -Name "Listening ports" `
            -Status "FAIL" `
            -Details $_.Exception.Message
    }
}

# ============================================================
# UDP PORTS
# ============================================================

function Test-UDPPorts {

    Write-Log "Auditing UDP endpoints..."

    if (-not (Test-CommandAvailable "Get-NetUDPEndpoint")) {
        Add-AuditResult `
            -Category "Network" `
            -Name "UDP endpoints" `
            -Status "WARN" `
            -Details "Get-NetUDPEndpoint unavailable"

        return
    }

    try {

        $UDP = @(
            Get-NetUDPEndpoint -ErrorAction Stop |
            Sort-Object LocalPort |
            Select-Object -Unique LocalAddress, LocalPort, OwningProcess
        )

        Add-AuditResult `
            -Category "Network" `
            -Name "UDP endpoints" `
            -Status "INFO" `
            -Details "$($UDP.Count) endpoints detected"
    }
    catch {
        Add-AuditResult `
            -Category "Network" `
            -Name "UDP audit" `
            -Status "WARN" `
            -Details $_.Exception.Message
    }
}

# ============================================================
# RDP AUDIT
# ============================================================

function Test-RDP {

    Write-Log "Auditing RDP..."

    try {

        $Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"

        $Value = Get-ItemPropertyValue `
            -Path $Path `
            -Name "fDenyTSConnections" `
            -ErrorAction Stop

        if ($Value -eq 1) {

            Add-AuditResult `
                -Category "RDP" `
                -Name "Remote Desktop" `
                -Status "OK" `
                -Details "Disabled"
        }
        else {

            Add-AuditResult `
                -Category "RDP" `
                -Name "Remote Desktop" `
                -Status "WARN" `
                -Details "Enabled"
        }
    }
    catch {
        Add-AuditResult `
            -Category "RDP" `
            -Name "Remote Desktop" `
            -Status "WARN" `
            -Details $_.Exception.Message
    }
}

# ============================================================
# SMB AUDIT
# ============================================================

function Test-SMB {

    Write-Log "Auditing SMB..."

    if (-not (Test-CommandAvailable "Get-SmbServerConfiguration")) {

        Add-AuditResult `
            -Category "SMB" `
            -Name "SMB audit" `
            -Status "WARN" `
            -Details "SMB cmdlets unavailable"

        return
    }

    try {

        $SMB = Get-SmbServerConfiguration -ErrorAction Stop

        $SMB1Property = $SMB.PSObject.Properties[
            "EnableSMB1Protocol"
        ]

        if ($null -eq $SMB1Property) {

            Add-AuditResult `
                -Category "SMB" `
                -Name "SMB1" `
                -Status "INFO" `
                -Details "SMB1 property is not exposed"

        }
        elseif ([bool]$SMB1Property.Value) {

            Add-AuditResult `
                -Category "SMB" `
                -Name "SMB1" `
                -Status "WARN" `
                -Details "SMB1 is enabled"

        }
        else {

            Add-AuditResult `
                -Category "SMB" `
                -Name "SMB1" `
                -Status "OK" `
                -Details "SMB1 is disabled"
        }
    }
    catch {

        Add-AuditResult `
            -Category "SMB" `
            -Name "SMB audit" `
            -Status "WARN" `
            -Details $_.Exception.Message
    }
}

# ============================================================
# WINRM
# ============================================================

function Test-WinRM {

    Write-Log "Auditing WinRM..."

    try {

        $Service = Get-Service `
            -Name WinRM `
            -ErrorAction Stop

        if ($Service.Status -eq "Running") {

            Add-AuditResult `
                -Category "Remote Management" `
                -Name "WinRM" `
                -Status "WARN" `
                -Details "Running"
        }
        else {

            Add-AuditResult `
                -Category "Remote Management" `
                -Name "WinRM" `
                -Status "OK" `
                -Details "$($Service.Status)"
        }
    }
    catch {

        Add-AuditResult `
            -Category "Remote Management" `
            -Name "WinRM" `
            -Status "INFO" `
            -Details "Service not present"
    }
}

# ============================================================
# NETBIOS
# ============================================================

function Test-NetBIOS {

    Write-Log "Auditing NetBIOS..."

    try {

        $Adapters = @(
            Get-CimInstance Win32_NetworkAdapterConfiguration |
            Where-Object {
                $_.IPEnabled -eq $true
            }
        )

        if ($Adapters.Count -eq 0) {

            Add-AuditResult `
                -Category "Network" `
                -Name "NetBIOS" `
                -Status "INFO" `
                -Details "No active IP adapters found"

            return
        }

        foreach ($Adapter in $Adapters) {

            if ($Adapter.TcpipNetbiosOptions -eq 2) {

                Add-AuditResult `
                    -Category "Network" `
                    -Name "NetBIOS - $($Adapter.Description)" `
                    -Status "OK" `
                    -Details "Disabled"
            }
            else {

                Add-AuditResult `
                    -Category "Network" `
                    -Name "NetBIOS - $($Adapter.Description)" `
                    -Status "WARN" `
                    -Details "Enabled or default"
            }
        }
    }
    catch {

        Add-AuditResult `
            -Category "Network" `
            -Name "NetBIOS audit" `
            -Status "WARN" `
            -Details $_.Exception.Message
    }
}

# ============================================================
# LLMNR
# ============================================================

function Test-LLMNR {

    Write-Log "Auditing LLMNR..."

    try {

        $Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"

        if (-not (Test-Path $Path)) {

            Add-AuditResult `
                -Category "Network" `
                -Name "LLMNR" `
                -Status "WARN" `
                -Details "Policy not configured"

            return
        }

        $Value = Get-ItemProperty `
            -Path $Path `
            -Name EnableMulticast `
            -ErrorAction SilentlyContinue

        if ($null -eq $Value) {

            Add-AuditResult `
                -Category "Network" `
                -Name "LLMNR" `
                -Status "WARN" `
                -Details "Policy value not configured"

            return
        }

        if ($Value.EnableMulticast -eq 0) {

            Add-AuditResult `
                -Category "Network" `
                -Name "LLMNR" `
                -Status "OK" `
                -Details "Disabled"
        }
        else {

            Add-AuditResult `
                -Category "Network" `
                -Name "LLMNR" `
                -Status "WARN" `
                -Details "Enabled"
        }
    }
    catch {

        Add-AuditResult `
            -Category "Network" `
            -Name "LLMNR audit" `
            -Status "WARN" `
            -Details $_.Exception.Message
    }
}

# ============================================================
# DEFENDER
# ============================================================

function Test-Defender {

    Write-Log "Auditing Microsoft Defender..."

    if (-not (Test-CommandAvailable "Get-MpComputerStatus")) {

        Add-AuditResult `
            -Category "Defender" `
            -Name "Defender audit" `
            -Status "WARN" `
            -Details "Microsoft Defender cmdlets unavailable"

        return
    }

    try {

        $Status = Get-MpComputerStatus -ErrorAction Stop

        if ($Status.RealTimeProtectionEnabled) {

            Add-AuditResult `
                -Category "Defender" `
                -Name "Real-time protection" `
                -Status "OK" `
                -Details "Enabled"
        }
        else {

            Add-AuditResult `
                -Category "Defender" `
                -Name "Real-time protection" `
                -Status "FAIL" `
                -Details "Disabled"
        }

        if ($Status.AntivirusEnabled) {

            Add-AuditResult `
                -Category "Defender" `
                -Name "Antivirus" `
                -Status "OK" `
                -Details "Enabled"
        }
        else {

            Add-AuditResult `
                -Category "Defender" `
                -Name "Antivirus" `
                -Status "FAIL" `
                -Details "Disabled"
        }

        Add-AuditResult `
            -Category "Defender" `
            -Name "Engine version" `
            -Status "INFO" `
            -Details "$($Status.AMEngineVersion)"
    }
    catch {

        Add-AuditResult `
            -Category "Defender" `
            -Name "Defender audit" `
            -Status "WARN" `
            -Details $_.Exception.Message
    }
}

# ============================================================
# ASR AUDIT
# ============================================================

function Test-ASR {

    Write-Log "Auditing ASR rules..."

    if (-not (Test-CommandAvailable "Get-MpPreference")) {

        Add-AuditResult `
            -Category "Defender ASR" `
            -Name "ASR audit" `
            -Status "WARN" `
            -Details "Get-MpPreference unavailable"

        return
    }

    try {

        $Preference = Get-MpPreference -ErrorAction Stop

        $Ids = @(
            $Preference.AttackSurfaceReductionRules_Ids
        )

        $Actions = @(
            $Preference.AttackSurfaceReductionRules_Actions
        )

        if ($Ids.Count -eq 0) {

            Add-AuditResult `
                -Category "Defender ASR" `
                -Name "ASR rules" `
                -Status "WARN" `
                -Details "No configured ASR rules"

            return
        }

        Add-AuditResult `
            -Category "Defender ASR" `
            -Name "ASR rules" `
            -Status "INFO" `
            -Details "$($Ids.Count) configured rules"

        for ($i = 0; $i -lt $Ids.Count; $i++) {

            $Action = "Unknown"

            if ($i -lt $Actions.Count) {
                $Action = $Actions[$i]
            }

            Add-AuditResult `
                -Category "Defender ASR" `
                -Name "$($Ids[$i])" `
                -Status "INFO" `
                -Details "Action=$Action"
        }
    }
    catch {

        Add-AuditResult `
            -Category "Defender ASR" `
            -Name "ASR audit" `
            -Status "WARN" `
            -Details $_.Exception.Message
    }
}

# ============================================================
# POWERSHELL V2 AUDIT
# ============================================================

function Test-PowerShellV2 {

    Write-Log "Auditing PowerShell v2..."

    if (-not (Test-CommandAvailable "Get-WindowsOptionalFeature")) {

        Add-AuditResult `
            -Category "PowerShell" `
            -Name "PowerShell v2" `
            -Status "WARN" `
            -Details "Windows optional feature cmdlet unavailable"

        return
    }

    try {

        $Features = @(
            Get-WindowsOptionalFeature `
                -Online `
                -ErrorAction Stop
        )

        $Feature = @(
            $Features |
            Where-Object {
                $_.FeatureName -match "PowerShellV2"
            }
        )

        if ($Feature.Count -eq 0) {

            Add-AuditResult `
                -Category "PowerShell" `
                -Name "PowerShell v2" `
                -Status "OK" `
                -Details "Feature not installed"

            return
        }

        foreach ($Item in $Feature) {

            if ($Item.State -eq "Disabled") {

                Add-AuditResult `
                    -Category "PowerShell" `
                    -Name "PowerShell v2" `
                    -Status "OK" `
                    -Details "$($Item.FeatureName): Disabled"
            }
            else {

                Add-AuditResult `
                    -Category "PowerShell" `
                    -Name "PowerShell v2" `
                    -Status "WARN" `
                    -Details "$($Item.FeatureName): $($Item.State)"
            }
        }
    }
    catch {

        Add-AuditResult `
            -Category "PowerShell" `
            -Name "PowerShell v2 audit" `
            -Status "WARN" `
            -Details $_.Exception.Message
    }
}

# ============================================================
# TLS AUDIT
# ============================================================

function Test-TLS {

    Write-Log "Auditing TLS 1.0 / 1.1..."

    foreach ($Protocol in @("TLS 1.0", "TLS 1.1")) {

        $ServerPath =
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server"

        $ClientPath =
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Client"

        $ServerDisabled = $false
        $ClientDisabled = $false

        if (Test-Path $ServerPath) {

            $Value = Get-ItemProperty `
                -Path $ServerPath `
                -Name Enabled `
                -ErrorAction SilentlyContinue

            if ($null -ne $Value -and $Value.Enabled -eq 0) {
                $ServerDisabled = $true
            }
        }

        if (Test-Path $ClientPath) {

            $Value = Get-ItemProperty `
                -Path $ClientPath `
                -Name Enabled `
                -ErrorAction SilentlyContinue

            if ($null -ne $Value -and $Value.Enabled -eq 0) {
                $ClientDisabled = $true
            }
        }

        if ($ServerDisabled -and $ClientDisabled) {

            Add-AuditResult `
                -Category "TLS" `
                -Name $Protocol `
                -Status "OK" `
                -Details "Disabled for client and server"
        }
        else {

            Add-AuditResult `
                -Category "TLS" `
                -Name $Protocol `
                -Status "WARN" `
                -Details "Not explicitly disabled for both client and server"
        }
    }
}

# ============================================================
# PASSWORD POLICY
# ============================================================

function Test-PasswordPolicy {

    Write-Log "Auditing password policy..."

    $Temp = Join-Path `
        $env:TEMP `
        "fullhard-security-$TimeStamp.cfg"

    try {

        $Result = secedit /export /cfg $Temp /quiet 2>&1

        if (-not (Test-Path $Temp)) {

            throw "secedit did not create the exported policy file."
        }

        $Content = Get-Content `
            $Temp `
            -Raw `
            -ErrorAction Stop

        $Length = 0
        $Complexity = 0

        if ($Content -match "MinimumPasswordLength\s*=\s*(\d+)") {
            $Length = [int]$Matches[1]
        }

        if ($Content -match "PasswordComplexity\s*=\s*(\d+)") {
            $Complexity = [int]$Matches[1]
        }

        if ($Length -ge 12) {

            Add-AuditResult `
                -Category "Authentication" `
                -Name "Minimum password length" `
                -Status "OK" `
                -Details "$Length"
        }
        else {

            Add-AuditResult `
                -Category "Authentication" `
                -Name "Minimum password length" `
                -Status "WARN" `
                -Details "$Length"
        }

        if ($Complexity -eq 1) {

            Add-AuditResult `
                -Category "Authentication" `
                -Name "Password complexity" `
                -Status "OK" `
                -Details "Enabled"
        }
        else {

            Add-AuditResult `
                -Category "Authentication" `
                -Name "Password complexity" `
                -Status "WARN" `
                -Details "Disabled"
        }
    }
    catch {

        Add-AuditResult `
            -Category "Authentication" `
            -Name "Password policy" `
            -Status "WARN" `
            -Details $_.Exception.Message
    }
    finally {

        Remove-Item `
            $Temp `
            -Force `
            -ErrorAction SilentlyContinue
    }
}

# ============================================================
# AUDIT POLICY
# ============================================================

function Test-AuditPolicy {

    Write-Log "Auditing Windows audit policy..."

    if (-not (Test-CommandAvailable "auditpol.exe")) {

        Add-AuditResult `
            -Category "Auditing" `
            -Name "Audit policy" `
            -Status "WARN" `
            -Details "auditpol.exe unavailable"

        return
    }

    try {

        $Output = auditpol /get /category:* 2>&1

        $File = Join-Path `
            $ReportPath `
            "auditpol-$TimeStamp.txt"

        $Output |
            Out-File `
                -FilePath $File `
                -Encoding UTF8

        Add-AuditResult `
            -Category "Auditing" `
            -Name "Audit policy" `
            -Status "INFO" `
            -Details "Saved to $File"
    }
    catch {

        Add-AuditResult `
            -Category "Auditing" `
            -Name "Audit policy" `
            -Status "WARN" `
            -Details $_.Exception.Message
    }
}

# ============================================================
# NETWORK ADAPTERS
# ============================================================

function Test-NetworkAdapters {

    Write-Log "Auditing network adapters..."

    if (-not (Test-CommandAvailable "Get-NetAdapter")) {

        Add-AuditResult `
            -Category "Network" `
            -Name "Network adapters" `
            -Status "WARN" `
            -Details "Get-NetAdapter unavailable"

        return
    }

    try {

        $Adapters = @(
            Get-NetAdapter -ErrorAction Stop |
            Where-Object {
                $_.Status -eq "Up"
            }
        )

        foreach ($Adapter in $Adapters) {

            $IPv6 = Get-NetAdapterBinding `
                -Name $Adapter.Name `
                -ComponentID "ms_tcpip6" `
                -ErrorAction SilentlyContinue

            if ($null -eq $IPv6) {

                Add-AuditResult `
                    -Category "Network" `
                    -Name "IPv6 $($Adapter.Name)" `
                    -Status "INFO" `
                    -Details "Binding information unavailable"

                continue
            }

            if ($IPv6.Enabled) {

                Add-AuditResult `
                    -Category "Network" `
                    -Name "IPv6 $($Adapter.Name)" `
                    -Status "OK" `
                    -Details "Enabled"
            }
            else {

                Add-AuditResult `
                    -Category "Network" `
                    -Name "IPv6 $($Adapter.Name)" `
                    -Status "WARN" `
                    -Details "Disabled"
            }
        }
    }
    catch {

        Add-AuditResult `
            -Category "Network" `
            -Name "Network adapters" `
            -Status "WARN" `
            -Details $_.Exception.Message
    }
}

# ============================================================
# SERVICES AUDIT
# ============================================================

function Test-SensitiveServices {

    Write-Log "Auditing sensitive services..."

    $Services = @(
        "RemoteRegistry",
        "WinRM",
        "TermService",
        "SSDPSRV",
        "upnphost"
    )

    foreach ($Name in $Services) {

        try {

            $Service = Get-Service `
                -Name $Name `
                -ErrorAction Stop

            if ($Service.Status -eq "Running") {

                Add-AuditResult `
                    -Category "Services" `
                    -Name $Name `
                    -Status "WARN" `
                    -Details "Running"
            }
            else {

                Add-AuditResult `
                    -Category "Services" `
                    -Name $Name `
                    -Status "OK" `
                    -Details "$($Service.Status)"
            }
        }
        catch {

            Add-AuditResult `
                -Category "Services" `
                -Name $Name `
                -Status "INFO" `
                -Details "Not installed"
        }
    }
}

# ============================================================
# COMPLETE AUDIT
# ============================================================

function Invoke-Audit {

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " FULLHARD - SECURITY AUDIT" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""

    $script:AuditResults.Clear()

    Get-SystemInformation
    Test-Firewall
    Test-ListeningPorts
    Test-UDPPorts
    Test-RDP
    Test-SMB
    Test-WinRM
    Test-NetBIOS
    Test-LLMNR
    Test-Defender
    Test-ASR
    Test-PowerShellV2
    Test-TLS
    Test-PasswordPolicy
    Test-AuditPolicy
    Test-NetworkAdapters
    Test-SensitiveServices

    return $script:AuditResults
}

# ============================================================
# BACKUP
# ============================================================

function Invoke-Backup {

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Yellow
    Write-Host " CREATING BACKUP" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Yellow
    Write-Host ""

    # --------------------------------------------------------
    # Firewall
    # --------------------------------------------------------

    try {

        $File = Join-Path $BackupPath "firewall.wfw"

        netsh advfirewall export $File 2>&1 | Out-Null

        if (Test-Path $File) {
            Write-Log "Firewall backup created." "OK"
        }
        else {
            Write-Log "Firewall backup file was not created." "WARN"
        }
    }
    catch {
        Write-Log "Firewall backup failed: $($_.Exception.Message)" "WARN"
    }

    # --------------------------------------------------------
    # LSA
    # --------------------------------------------------------

    try {

        $File = Join-Path $BackupPath "LSA.reg"

        reg.exe export `
            "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
            $File `
            /y 2>&1 | Out-Null

        if (Test-Path $File) {
            Write-Log "LSA registry backup created." "OK"
        }
        else {
            Write-Log "LSA registry backup was not created." "WARN"
        }
    }
    catch {
        Write-Log "LSA backup failed: $($_.Exception.Message)" "WARN"
    }

    # --------------------------------------------------------
    # RDP
    # --------------------------------------------------------

    try {

        $File = Join-Path $BackupPath "RDP.reg"

        reg.exe export `
            "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" `
            $File `
            /y 2>&1 | Out-Null

        if (Test-Path $File) {
            Write-Log "RDP registry backup created." "OK"
        }
        else {
            Write-Log "RDP registry backup was not created." "WARN"
        }
    }
    catch {
        Write-Log "RDP backup failed: $($_.Exception.Message)" "WARN"
    }

    # --------------------------------------------------------
    # SCHANNEL
    # --------------------------------------------------------

    try {

        $File = Join-Path $BackupPath "SCHANNEL.reg"

        reg.exe export `
            "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" `
            $File `
            /y 2>&1 | Out-Null

        if (Test-Path $File) {
            Write-Log "SCHANNEL backup created." "OK"
        }
        else {
            Write-Log "SCHANNEL backup was not created." "WARN"
        }
    }
    catch {
        Write-Log "SCHANNEL backup failed: $($_.Exception.Message)" "WARN"
    }

    # --------------------------------------------------------
    # Audit policy
    # --------------------------------------------------------

    try {

        $File = Join-Path $BackupPath "audit-policy.csv"

        auditpol /backup /file:$File 2>&1 | Out-Null

        if (Test-Path $File) {
            Write-Log "Audit policy backup created." "OK"
        }
        else {
            Write-Log "Audit policy backup was not created." "WARN"
        }
    }
    catch {
        Write-Log "Audit policy backup failed: $($_.Exception.Message)" "WARN"
    }

    # --------------------------------------------------------
    # Defender
    # --------------------------------------------------------

    try {

        if (Test-CommandAvailable "Get-MpPreference") {

            Get-MpPreference |
                Out-File `
                    -FilePath (Join-Path $BackupPath "Defender-Preferences.txt") `
                    -Encoding UTF8

            Write-Log "Defender configuration backup created." "OK"
        }
        else {

            Write-Log "Defender cmdlets unavailable. Defender backup skipped." "WARN"
        }
    }
    catch {
        Write-Log "Defender backup failed: $($_.Exception.Message)" "WARN"
    }

    # --------------------------------------------------------
    # Services
    # --------------------------------------------------------

    try {

        Get-Service |
            Select-Object Name, Status, StartType |
            Export-Csv `
                -Path (Join-Path $BackupPath "Services.csv") `
                -NoTypeInformation `
                -Encoding UTF8

        Write-Log "Service inventory backup created." "OK"
    }
    catch {
        Write-Log "Service backup failed: $($_.Exception.Message)" "WARN"
    }

    # --------------------------------------------------------
    # Firewall rules
    # --------------------------------------------------------

    try {

        if (Test-CommandAvailable "Get-NetFirewallRule") {

            Get-NetFirewallRule |
                Select-Object `
                    DisplayName,
                    Enabled,
                    Direction,
                    Action,
                    Profile |
                Export-Csv `
                    -Path (Join-Path $BackupPath "Firewall-Rules.csv") `
                    -NoTypeInformation `
                    -Encoding UTF8

            Write-Log "Firewall rules inventory created." "OK"
        }
    }
    catch {
        Write-Log "Firewall rules backup failed: $($_.Exception.Message)" "WARN"
    }

    Write-Log "Backup directory: $BackupPath" "OK"
}

# ============================================================
# FIREWALL HARDENING
# ============================================================

function Set-FirewallHardening {

    Write-Log "Applying firewall hardening..."

    try {

        Set-NetFirewallProfile `
            -Profile Domain,Private,Public `
            -Enabled True `
            -DefaultInboundAction Block `
            -DefaultOutboundAction Allow `
            -LogBlocked True `
            -LogAllowed False `
            -LogMaxSizeKilobytes 32768 `
            -ErrorAction Stop

        Write-Log `
            "Firewall hardened: inbound Block / outbound Allow." `
            "OK"
    }
    catch {

        Write-Log `
            "Firewall hardening failed: $($_.Exception.Message)" `
            "ERROR"
    }
}

# ============================================================
# RDP HARDENING
# ============================================================

function Set-RDPHardening {

    if ($EnableRDP) {

        Write-Log "RDP requested: enabling with NLA..."

        try {

            $Path =
                "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"

            Set-ItemProperty `
                -Path $Path `
                -Name fDenyTSConnections `
                -Value 0 `
                -Type DWord `
                -ErrorAction Stop

            $RdpTcpPath =
                "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

            if (Test-Path $RdpTcpPath) {

                Set-ItemProperty `
                    -Path $RdpTcpPath `
                    -Name UserAuthentication `
                    -Value 1 `
                    -Type DWord `
                    -ErrorAction Stop
            }

            Set-Service `
                -Name TermService `
                -StartupType Manual `
                -ErrorAction Stop

            Enable-NetFirewallRule `
                -DisplayGroup "Remote Desktop" `
                -ErrorAction SilentlyContinue

            Write-Log "RDP enabled with NLA." "OK"
        }
        catch {

            Write-Log `
                "RDP configuration failed: $($_.Exception.Message)" `
                "ERROR"
        }
    }
    else {

        Write-Log "Disabling RDP..."

        try {

            Set-ItemProperty `
                -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
                -Name fDenyTSConnections `
                -Value 1 `
                -Type DWord `
                -ErrorAction Stop

            Disable-NetFirewallRule `
                -DisplayGroup "Remote Desktop" `
                -ErrorAction SilentlyContinue

            Write-Log "RDP disabled." "OK"
        }
        catch {

            Write-Log `
                "RDP hardening failed: $($_.Exception.Message)" `
                "WARN"
        }
    }
}

# ============================================================
# SMB HARDENING
# ============================================================

function Set-SMBHardening {

    Write-Log "Applying SMB hardening..."

    if (-not (Test-CommandAvailable "Get-SmbServerConfiguration")) {

        Write-Log "SMB cmdlets unavailable. SMB hardening skipped." "WARN"
        return
    }

    try {

        $SMB = Get-SmbServerConfiguration -ErrorAction Stop

        $Property = $SMB.PSObject.Properties[
            "EnableSMB1Protocol"
        ]

        if ($null -eq $Property) {

            Write-Log `
                "SMB1 property is not exposed. SMB1 change skipped." `
                "INFO"

            return
        }

        if ([bool]$Property.Value) {

            Set-SmbServerConfiguration `
                -EnableSMB1Protocol $false `
                -Force `
                -ErrorAction Stop

            Write-Log "SMBv1 disabled." "OK"
        }
        else {

            Write-Log "SMBv1 already disabled." "OK"
        }
    }
    catch {

        Write-Log `
            "SMB hardening failed: $($_.Exception.Message)" `
            "WARN"
    }
}

# ============================================================
# NETWORK HARDENING
# ============================================================

function Set-NetworkHardening {

    Write-Log "Applying network hardening..."

    # --------------------------------------------------------
    # LLMNR
    # --------------------------------------------------------

    try {

        $Path =
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"

        if (-not (Test-Path $Path)) {
            New-Item `
                -Path $Path `
                -Force `
                -ErrorAction Stop | Out-Null
        }

        Set-ItemProperty `
            -Path $Path `
            -Name EnableMulticast `
            -Value 0 `
            -Type DWord `
            -ErrorAction Stop

        Write-Log "LLMNR disabled." "OK"
    }
    catch {

        Write-Log `
            "LLMNR hardening failed: $($_.Exception.Message)" `
            "WARN"
    }

    # --------------------------------------------------------
    # LLTD responder
    # --------------------------------------------------------

    try {

        if (Test-CommandAvailable "Get-NetAdapterBinding") {

            $Bindings = @(
                Get-NetAdapterBinding `
                    -Name "*" `
                    -ComponentID "ms_rspndr" `
                    -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Enabled -eq $true
                }
            )

            foreach ($Binding in $Bindings) {

                Disable-NetAdapterBinding `
                    -Name $Binding.Name `
                    -ComponentID "ms_rspndr" `
                    -ErrorAction SilentlyContinue | Out-Null
            }

            Write-Log `
                "LLTD responder disabled where available." `
                "OK"
        }
    }
    catch {

        Write-Log `
            "LLTD configuration skipped: $($_.Exception.Message)" `
            "WARN"
    }

    # --------------------------------------------------------
    # Network Discovery
    # --------------------------------------------------------

    if ($DisableNetworkDiscovery) {

        try {

            $Rules = @(
                Get-NetFirewallRule `
                    -DisplayGroup "Network Discovery" `
                    -ErrorAction SilentlyContinue
            )

            if ($Rules.Count -gt 0) {

                $Rules |
                    Disable-NetFirewallRule `
                    -ErrorAction SilentlyContinue

                Write-Log `
                    "Network Discovery firewall rules disabled." `
                    "OK"
            }
            else {

                Write-Log `
                    "Network Discovery rules not found." `
                    "INFO"
            }
        }
        catch {

            Write-Log `
                "Network Discovery hardening failed: $($_.Exception.Message)" `
                "WARN"
        }
    }
    else {

        Write-Log `
            "Network Discovery left unchanged." `
            "INFO"
    }
}

# ============================================================
# SERVICE HARDENING
# ============================================================

function Set-ServiceHardening {

    Write-Log "Applying conservative service hardening..."

    # Deliberately limited list.
    #
    # WinRM and TermService are NOT disabled here because
    # their state is controlled separately.
    #
    # SSDPSRV/upnphost are optional and can affect discovery/
    # UPnP functionality, so only these explicitly unnecessary
    # services are targeted.

    $Targets = @(
        "RemoteRegistry"
    )

    foreach ($Name in $Targets) {

        try {

            $Service = Get-Service `
                -Name $Name `
                -ErrorAction Stop

            if ($Service.Status -eq "Running") {

                Stop-Service `
                    -Name $Name `
                    -Force `
                    -ErrorAction SilentlyContinue
            }

            Set-Service `
                -Name $Name `
                -StartupType Disabled `
                -ErrorAction Stop

            Write-Log "$Name disabled." "OK"
        }
        catch {

            Write-Log `
                "$Name skipped: $($_.Exception.Message)" `
                "WARN"
        }
    }

    Write-Log `
        "Other Windows services were intentionally left unchanged." `
        "INFO"
}

# ============================================================
# POWERSHELL V2 HARDENING
# ============================================================

function Set-PowerShellHardening {

    Write-Log "Disabling PowerShell v2 if installed..."

    if (-not (Test-CommandAvailable "Get-WindowsOptionalFeature")) {

        Write-Log `
            "Windows optional feature cmdlet unavailable." `
            "WARN"

        return
    }

    try {

        $Features = @(
            Get-WindowsOptionalFeature `
                -Online `
                -ErrorAction Stop
        )

        $FeaturesToDisable = @(
            $Features |
            Where-Object {
                $_.FeatureName -match "PowerShellV2" -and
                $_.State -ne "Disabled"
            }
        )

        if ($FeaturesToDisable.Count -eq 0) {

            Write-Log `
                "PowerShell v2 already disabled/not installed." `
                "OK"

            return
        }

        foreach ($Feature in $FeaturesToDisable) {

            Disable-WindowsOptionalFeature `
                -Online `
                -FeatureName $Feature.FeatureName `
                -NoRestart `
                -ErrorAction Stop | Out-Null

            Write-Log `
                "$($Feature.FeatureName) disabled." `
                "OK"
        }
    }
    catch {

        Write-Log `
            "PowerShell v2 hardening failed: $($_.Exception.Message)" `
            "WARN"
    }
}

# ============================================================
# TLS HARDENING
# ============================================================

function Set-TLSHardening {

    Write-Log "Disabling TLS 1.0 and TLS 1.1..."

    foreach ($Protocol in @("TLS 1.0", "TLS 1.1")) {

        foreach ($Role in @("Server", "Client")) {

            $Path =
                "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\$Role"

            try {

                if (-not (Test-Path $Path)) {

                    New-Item `
                        -Path $Path `
                        -Force `
                        -ErrorAction Stop | Out-Null
                }

                Set-ItemProperty `
                    -Path $Path `
                    -Name Enabled `
                    -Value 0 `
                    -Type DWord `
                    -ErrorAction Stop

                Set-ItemProperty `
                    -Path $Path `
                    -Name DisabledByDefault `
                    -Value 1 `
                    -Type DWord `
                    -ErrorAction Stop
            }
            catch {

                Write-Log `
                    "$Protocol $Role failed: $($_.Exception.Message)" `
                    "WARN"
            }
        }

        Write-Log "$Protocol disabled." "OK"
    }
}

# ============================================================
# DEFENDER HARDENING
# ============================================================

function Set-DefenderHardening {

    Write-Log "Applying Defender hardening..."

    if (-not (Test-CommandAvailable "Set-MpPreference")) {

        Write-Log `
            "Set-MpPreference unavailable. Defender hardening skipped." `
            "WARN"

        return
    }

    # --------------------------------------------------------
    # Core protection
    # --------------------------------------------------------

    try {

        Set-MpPreference `
            -DisableRealtimeMonitoring $false `
            -DisableBehaviorMonitoring $false `
            -DisableBlockAtFirstSeen $false `
            -DisableIOAVProtection $false `
            -DisableScriptScanning $false `
            -DisableArchiveScanning $false `
            -DisableEmailScanning $false `
            -DisableRemovableDriveScanning $false `
            -ErrorAction Stop

        Write-Log `
            "Defender real-time and scanning protections enabled." `
            "OK"
    }
    catch {

        Write-Log `
            "Defender base hardening failed: $($_.Exception.Message)" `
            "WARN"
    }

    # --------------------------------------------------------
    # Cloud protection
    # --------------------------------------------------------

    try {

        Set-MpPreference `
            -MAPSReporting Advanced `
            -SubmitSamplesConsent SendSafeSamples `
            -CloudBlockLevel High `
            -CloudExtendedTimeout 50 `
            -ErrorAction Stop

        Write-Log `
            "Defender cloud protection strengthened." `
            "OK"
    }
    catch {

        Write-Log `
            "Cloud protection configuration skipped: $($_.Exception.Message)" `
            "WARN"
    }

    # --------------------------------------------------------
    # Signature update
    # --------------------------------------------------------

    try {

        if (Test-CommandAvailable "Update-MpSignature") {

            Update-MpSignature `
                -ErrorAction SilentlyContinue

            Write-Log `
                "Defender signature update requested." `
                "OK"
        }
    }
    catch {

        Write-Log `
            "Defender signature update failed: $($_.Exception.Message)" `
            "WARN"
    }
}

# ============================================================
# ASR HARDENING
# ============================================================

function Set-ASRHardening {

    Write-Log "Configuring ASR rules..."

    if (-not (Test-CommandAvailable "Set-MpPreference")) {

        Write-Log `
            "Set-MpPreference unavailable. ASR configuration skipped." `
            "WARN"

        return
    }

    # Selected conservative ASR rules.
    #
    # Default:
    #   Audit = 2
    #
    # With:
    #   -EnableASRBlock
    #   Block = 1

    $Rules = @(
        "56a863a9-875e-4185-98a7-b882c64b5ce5" # Block abuse of exploited vulnerable signed drivers
        "26190899-1602-49e8-8b27-eb1d0a1ce869" # Block Office communication applications from creating child processes
        "3b576869-a4ec-4529-8536-b80a7769e899" # Block Office applications from creating executable content
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a" # Block all Office applications from creating child processes
        "d3e037e1-3eb8-44c8-a917-57927947596d" # Block JavaScript or VBScript from launching downloaded executable content
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc" # Block execution of potentially obfuscated scripts
    )

    $Action = 2

    if ($EnableASRBlock) {
        $Action = 1
    }

    try {

        # Read current configuration.
        $Current = Get-MpPreference -ErrorAction Stop

        $CurrentIds = @(
            $Current.AttackSurfaceReductionRules_Ids
        )

        $CurrentActions = @(
            $Current.AttackSurfaceReductionRules_Actions
        )

        # Build a dictionary of existing rules.
        $RuleMap = @{}

        for ($i = 0; $i -lt $CurrentIds.Count; $i++) {

            $Id = ([string]$CurrentIds[$i]).ToLowerInvariant()

            if ($Id -and $i -lt $CurrentActions.Count) {
                $RuleMap[$Id] = $CurrentActions[$i]
            }
        }

        # Update only our selected rules.
        foreach ($Rule in $Rules) {

            $RuleMap[$Rule.ToLowerInvariant()] = $Action
        }

        $FinalIds = @($RuleMap.Keys)

        $FinalActions = @(
            foreach ($Id in $FinalIds) {
                $RuleMap[$Id]
            }
        )

        # Set complete resulting configuration.
        Set-MpPreference `
            -AttackSurfaceReductionRules_Ids $FinalIds `
            -AttackSurfaceReductionRules_Actions $FinalActions `
            -ErrorAction Stop

        if ($Action -eq 1) {

            Write-Log `
                "Selected ASR rules configured in BLOCK mode." `
                "OK"
        }
        else {

            Write-Log `
                "Selected ASR rules configured in AUDIT mode." `
                "OK"
        }
    }
    catch {

        Write-Log `
            "ASR configuration failed: $($_.Exception.Message)" `
            "WARN"
    }
}

# ============================================================
# AUDIT POLICY HARDENING
# ============================================================

function Set-AuditPolicyHardening {

    Write-Log "Configuring Windows auditing..."

    $Categories = @(
        "Logon/Logoff"
        "Account Logon"
        "Account Management"
        "Policy Change"
        "System"
    )

    foreach ($Category in $Categories) {

        try {

            $Output = auditpol /set `
                /category:"$Category" `
                /success:enable `
                /failure:enable 2>&1

            if ($LASTEXITCODE -eq 0) {

                Write-Log `
                    "Audit enabled: $Category" `
                    "OK"
            }
            else {

                Write-Log `
                    "Audit category failed: $Category | $Output" `
                    "WARN"
            }
        }
        catch {

            Write-Log `
                "Audit category failed: $Category | $($_.Exception.Message)" `
                "WARN"
        }
    }
}

# ============================================================
# AUTOLOGON
# ============================================================

function Set-AutoLogonHardening {

    Write-Log "Disabling AutoAdminLogon..."

    try {

        $Path =
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

        Set-ItemProperty `
            -Path $Path `
            -Name AutoAdminLogon `
            -Value "0" `
            -ErrorAction Stop

        Write-Log "AutoAdminLogon disabled." "OK"
    }
    catch {

        Write-Log `
            "AutoAdminLogon configuration failed: $($_.Exception.Message)" `
            "WARN"
    }
}

# ============================================================
# HARDENING
# ============================================================

function Invoke-Hardening {

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host " APPLYING HARDENING" -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host ""

    Set-FirewallHardening
    Set-RDPHardening
    Set-SMBHardening
    Set-NetworkHardening
    Set-ServiceHardening
    Set-PowerShellHardening
    Set-TLSHardening
    Set-DefenderHardening
    Set-ASRHardening
    Set-AuditPolicyHardening
    Set-AutoLogonHardening

    Write-Log "Hardening phase completed." "OK"
}

# ============================================================
# REPORT
# ============================================================

function Save-AuditReport {

    param(
        [Parameter(Mandatory)]
        [ValidateSet("Before","After")]
        [string]$Prefix
    )

    if ($Prefix -eq "Before") {

        $Csv = $BeforeCsv
        $Txt = $BeforeTxt
    }
    else {

        $Csv = $AfterCsv
        $Txt = $AfterTxt
    }

    try {

        $AuditResults |
            Export-Csv `
                -Path $Csv `
                -NoTypeInformation `
                -Encoding UTF8

        $Lines =
            New-Object System.Collections.Generic.List[string]

        [void]$Lines.Add("FULLHARD SECURITY AUDIT")
        [void]$Lines.Add("Time: $(Get-Date)")
        [void]$Lines.Add("")

        [void]$Lines.Add("STATUS SUMMARY")
        [void]$Lines.Add("------------------------------")

        $OK = @(
            $AuditResults |
            Where-Object Status -eq "OK"
        ).Count

        $WARN = @(
            $AuditResults |
            Where-Object Status -eq "WARN"
        ).Count

        $FAIL = @(
            $AuditResults |
            Where-Object Status -eq "FAIL"
        ).Count

        $INFO = @(
            $AuditResults |
            Where-Object Status -eq "INFO"
        ).Count

        [void]$Lines.Add("OK   : $OK")
        [void]$Lines.Add("WARN : $WARN")
        [void]$Lines.Add("FAIL : $FAIL")
        [void]$Lines.Add("INFO : $INFO")
        [void]$Lines.Add("")

        foreach ($Result in $AuditResults) {

            $Status   = [string]$Result.Status
            $Category = [string]$Result.Category
            $Name     = [string]$Result.Name
            $Details  = [string]$Result.Details

            $Line =
                '[{0}] {1} | {2} | {3}' -f `
                    $Status,
                    $Category,
                    $Name,
                    $Details

            [void]$Lines.Add($Line)
        }

        $Lines |
            Out-File `
                -FilePath $Txt `
                -Encoding UTF8

        Write-Log "Report saved: $Txt" "OK"
        Write-Log "CSV saved: $Csv" "OK"
    }
    catch {

        Write-Log `
            "Report generation failed: $($_.Exception.Message)" `
            "ERROR"
    }
}

# ============================================================
# SUMMARY
# ============================================================

function Show-Summary {

    param(
        [Parameter(Mandatory)]
        [string]$Title
    )

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host " $Title" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green

    $OK = @(
        $AuditResults |
        Where-Object Status -eq "OK"
    ).Count

    $WARN = @(
        $AuditResults |
        Where-Object Status -eq "WARN"
    ).Count

    $FAIL = @(
        $AuditResults |
        Where-Object Status -eq "FAIL"
    ).Count

    $INFO = @(
        $AuditResults |
        Where-Object Status -eq "INFO"
    ).Count

    Write-Host ""
    Write-Host "OK   : $OK" -ForegroundColor Green
    Write-Host "WARN : $WARN" -ForegroundColor Yellow
    Write-Host "FAIL : $FAIL" -ForegroundColor Red
    Write-Host "INFO : $INFO" -ForegroundColor Cyan
    Write-Host ""
}

# ============================================================
# MAIN
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " FULLHARD - WINDOWS SERVER 2022" -ForegroundColor Cyan
Write-Host " Gaming + Browser Security Profile" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "1 - Audit only"
Write-Host "2 - Audit + Backup + Hardening + Post-Audit"
Write-Host "3 - Audit + Backup + Hardening + ASR BLOCK + Post-Audit"
Write-Host "Q - Exit"
Write-Host ""

# ============================================================
# MODE
# ============================================================

if ($AuditOnly) {

    $Mode = "1"
}
elseif ($ApplyHardening) {

    if ($EnableASRBlock) {
        $Mode = "3"
    }
    else {
        $Mode = "2"
    }
}
else {

    $Mode = Read-Host "Select mode"
}

if (
    $Mode -eq "Q" -or
    $Mode -eq "q"
) {

    Write-Log "User selected exit." "INFO"
    exit 0
}

if ($Mode -notin @("1","2","3")) {

    Write-Log "Invalid mode selected." "ERROR"
    exit 1
}

# ============================================================
# PRE-AUDIT
# ============================================================

Invoke-Audit

Save-AuditReport -Prefix "Before"

Show-Summary -Title "PRE-AUDIT"

# ============================================================
# AUDIT ONLY
# ============================================================

if ($Mode -eq "1") {

    Write-Host ""
    Write-Host `
        "AUDIT ONLY MODE - NO SYSTEM CHANGES WERE MADE." `
        -ForegroundColor Yellow

    Write-Host ""
    Write-Host "Reports:"
    Write-Host "  $ReportPath"
    Write-Host ""

    exit 0
}

# ============================================================
# CONFIRMATION
# ============================================================

Write-Host ""
Write-Host "WARNING:" -ForegroundColor Red
Write-Host `
    "The next phase will modify system security settings." `
    -ForegroundColor Yellow

Write-Host `
    "A backup will be created first." `
    -ForegroundColor Yellow

if ($EnableRDP) {

    Write-Host `
        "RDP will be ENABLED with NLA." `
        -ForegroundColor Yellow
}
else {

    Write-Host `
        "RDP will be DISABLED." `
        -ForegroundColor Yellow
}

if ($EnableASRBlock) {

    Write-Host `
        "Selected ASR rules will be configured in BLOCK mode." `
        -ForegroundColor Yellow
}
else {

    Write-Host `
        "Selected ASR rules will be configured in AUDIT mode." `
        -ForegroundColor Yellow
}

Write-Host ""

$Confirm = Read-Host "Type YES to continue"

if ($Confirm -cne "YES") {

    Write-Log "Hardening cancelled by user." "WARN"
    exit 0
}

# ============================================================
# BACKUP
# ============================================================

Invoke-Backup

# ============================================================
# HARDENING
# ============================================================

Invoke-Hardening

# ============================================================
# POST-AUDIT
# ============================================================

Write-Host ""
Write-Host `
    "Waiting 3 seconds before post-audit..." `
    -ForegroundColor Cyan

Start-Sleep -Seconds 3

Invoke-Audit

Save-AuditReport -Prefix "After"

Show-Summary -Title "POST-AUDIT"

# ============================================================
# FINAL
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " FULLHARD COMPLETED" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""

Write-Host "Reports:" -ForegroundColor Yellow
Write-Host "  $ReportPath"

Write-Host ""
Write-Host "Backup:" -ForegroundColor Yellow
Write-Host "  $BackupPath"

Write-Host ""
Write-Host "Main log:" -ForegroundColor Yellow
Write-Host "  $LogFile"

Write-Host ""
Write-Host "A reboot is recommended." -ForegroundColor Yellow
Write-Host ""

Write-Log "FullHard completed successfully." "OK"
