#requires -version 5.1

<#
.SYNOPSIS
    Kompleksowy, tylko-do-odczytu audyt bezpieczeństwa Windows 11.

.DESCRIPTION
    Skrypt nie zmienia konfiguracji systemu.
    Zbiera informacje dotyczące m.in.:

    - Microsoft Defender
    - Defender Firewall
    - BitLocker
    - TPM
    - Secure Boot
    - VBS / HVCI / Credential Guard
    - UAC
    - Windows Update
    - kont lokalnych
    - grup uprzywilejowanych
    - polityki haseł
    - polityki audytu
    - PowerShell
    - WinRM
    - RDP
    - SMB
    - NTLM
    - TLS / Schannel
    - usług
    - sterowników
    - portów nasłuchujących
    - połączeń sieciowych
    - udziałów
    - reguł Firewall
    - Defender ASR
    - Controlled Folder Access
    - Exploit Protection
    - AppLocker / WDAC
    - LSA Protection
    - Windows Security
    - event logów
    - autostartu
    - zadań harmonogramu
    - certyfikatów
    - istotnych ustawień rejestru
    - urządzeń USB
    - integralności systemu
    - wielu dodatkowych ustawień bezpieczeństwa.

.NOTES
    Read-only.
    Zalecane uruchomienie jako Administrator.
#>

$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# KONFIGURACJA
# ============================================================

$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Computer = $env:COMPUTERNAME

$OutputRoot = Join-Path $env:USERPROFILE "Desktop\Windows11-SecurityAudit_$TimeStamp"

New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
New-Item -ItemType Directory -Path "$OutputRoot\Data" -Force | Out-Null

$ReportCsv  = "$OutputRoot\SecurityAudit.csv"
$ReportJson = "$OutputRoot\SecurityAudit.json"
$ReportHtml = "$OutputRoot\SecurityAudit.html"
$ReportTxt  = "$OutputRoot\SecurityAudit.txt"

$Results = [System.Collections.Generic.List[object]]::new()

# ============================================================
# FUNKCJE
# ============================================================

function Add-Result {
    param(
        [string]$Category,
        [string]$Check,
        [ValidateSet("PASS","WARNING","FAIL","INFO","ERROR")]
        [string]$Status,
        [string]$Value = "",
        [string]$Recommendation = ""
    )

    $Results.Add([PSCustomObject]@{
        Time            = Get-Date
        Computer        = $Computer
        Category        = $Category
        Check           = $Check
        Status          = $Status
        Value           = $Value
        Recommendation  = $Recommendation
    })
}

function Get-RegValueSafe {
    param(
        [string]$Path,
        [string]$Name
    )

    try {
        return Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop
    }
    catch {
        return $null
    }
}

function Test-RegEquals {
    param(
        [string]$Path,
        [string]$Name,
        $Expected
    )

    $value = Get-RegValueSafe -Path $Path -Name $Name

    if ($null -eq $value) {
        return $false
    }

    return ($value -eq $Expected)
}

function Run-Check {
    param(
        [string]$Category,
        [string]$Check,
        [scriptblock]$Script
    )

    try {
        & $Script
    }
    catch {
        Add-Result `
            -Category $Category `
            -Check $Check `
            -Status ERROR `
            -Value $_.Exception.Message
    }
}

# ============================================================
# START
# ============================================================

Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " WINDOWS 11 SECURITY AUDIT" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Komputer: $Computer"
Write-Host "Raport:   $OutputRoot"
Write-Host ""

# ============================================================
# SYSTEM
# ============================================================

Run-Check "System" "Windows version" {
    $os = Get-CimInstance Win32_OperatingSystem

    Add-Result "System" "Windows version" INFO `
        "$($os.Caption) $($os.Version) Build $($os.BuildNumber)"

    Add-Result "System" "Architecture" INFO $os.OSArchitecture

    Add-Result "System" "Install date" INFO `
        ([Management.ManagementDateTimeConverter]::ToDateTime($os.InstallDate))
}

Run-Check "System" "Computer information" {
    $cs = Get-CimInstance Win32_ComputerSystem

    Add-Result "System" "Manufacturer" INFO $cs.Manufacturer
    Add-Result "System" "Model" INFO $cs.Model
    Add-Result "System" "Total RAM" INFO "$([math]::Round($cs.TotalPhysicalMemory / 1GB,2)) GB"
}

Run-Check "System" "System uptime" {
    $os = Get-CimInstance Win32_OperatingSystem
    $boot = $os.LastBootUpTime
    $uptime = (Get-Date) - $boot

    Add-Result "System" "Last boot" INFO $boot
    Add-Result "System" "Uptime" INFO $uptime.ToString()
}

# ============================================================
# SECURE BOOT
# ============================================================

Run-Check "Boot Security" "Secure Boot" {
    try {
        $secureBoot = Confirm-SecureBootUEFI

        if ($secureBoot) {
            Add-Result "Boot Security" "Secure Boot" PASS "Enabled"
        }
        else {
            Add-Result "Boot Security" "Secure Boot" FAIL `
                "Disabled" `
                "Enable Secure Boot in UEFI firmware."
        }
    }
    catch {
        Add-Result "Boot Security" "Secure Boot" WARNING `
            "Unavailable / Legacy BIOS / access denied"
    }
}

# ============================================================
# TPM
# ============================================================

Run-Check "TPM" "TPM presence" {
    $tpm = Get-Tpm

    if ($tpm.TpmPresent) {
        Add-Result "TPM" "TPM present" PASS "Yes"
    }
    else {
        Add-Result "TPM" "TPM present" FAIL `
            "No TPM detected" `
            "Windows 11 systems should normally use TPM 2.0."
    }

    Add-Result "TPM" "TPM ready" `
        ($(if ($tpm.TpmReady) {"PASS"} else {"WARNING"})) `
        $tpm.TpmReady
}

Run-Check "TPM" "TPM specification" {
    $tpm = Get-CimInstance -Namespace root/cimv2/security/microsofttpm `
        -ClassName Win32_Tpm

    if ($tpm) {
        Add-Result "TPM" "TPM manufacturer" INFO $tpm.ManufacturerIdTxt
        Add-Result "TPM" "TPM manufacturer version" INFO $tpm.ManufacturerVersion
    }
}

# ============================================================
# BITLOCKER
# ============================================================

Run-Check "BitLocker" "BitLocker volumes" {
    $volumes = Get-BitLockerVolume

    foreach ($v in $volumes) {

        $status = $v.VolumeStatus
        $protection = $v.ProtectionStatus

        if ($v.MountPoint -and $status -eq "FullyEncrypted") {

            if ($protection -eq "On") {
                $state = "PASS"
            }
            else {
                $state = "WARNING"
            }

            Add-Result "BitLocker" `
                "Volume $($v.MountPoint)" `
                $state `
                "Encryption=$status; Protection=$protection; Method=$($v.EncryptionMethod)" `
                "System/data volumes should normally have encryption and active protection."
        }
        else {
            Add-Result "BitLocker" `
                "Volume $($v.MountPoint)" `
                WARNING `
                "Encryption=$status; Protection=$protection"
        }

        Add-Result "BitLocker" `
            "$($v.MountPoint) Encryption method" `
            INFO `
            $v.EncryptionMethod

        foreach ($kp in $v.KeyProtector) {
            Add-Result "BitLocker" `
                "$($v.MountPoint) Key Protector" `
                INFO `
                $kp.KeyProtectorType
        }
    }
}

# ============================================================
# MICROSOFT DEFENDER
# ============================================================

Run-Check "Microsoft Defender" "Defender status" {

    $d = Get-MpComputerStatus

    Add-Result "Microsoft Defender" "Antivirus enabled" `
        ($(if ($d.AntivirusEnabled) {"PASS"} else {"FAIL"})) `
        $d.AntivirusEnabled

    Add-Result "Microsoft Defender" "Antispyware enabled" `
        ($(if ($d.AntispywareEnabled) {"PASS"} else {"FAIL"})) `
        $d.AntispywareEnabled

    Add-Result "Microsoft Defender" "Real-time protection" `
        ($(if ($d.RealTimeProtectionEnabled) {"PASS"} else {"FAIL"})) `
        $d.RealTimeProtectionEnabled

    Add-Result "Microsoft Defender" "Behavior monitoring" `
        ($(if ($d.BehaviorMonitorEnabled) {"PASS"} else {"WARNING"})) `
        $d.BehaviorMonitorEnabled

    Add-Result "Microsoft Defender" "IOAV protection" `
        ($(if ($d.IoavProtectionEnabled) {"PASS"} else {"WARNING"})) `
        $d.IoavProtectionEnabled

    Add-Result "Microsoft Defender" "On-access protection" `
        ($(if ($d.OnAccessProtectionEnabled) {"PASS"} else {"WARNING"})) `
        $d.OnAccessProtectionEnabled

    Add-Result "Microsoft Defender" "Tamper Protection" INFO `
        $d.IsTamperProtected

    Add-Result "Microsoft Defender" "Engine version" INFO `
        $d.AMEngineVersion

    Add-Result "Microsoft Defender" "Product version" INFO `
        $d.AMProductVersion

    Add-Result "Microsoft Defender" "Antivirus signature version" INFO `
        $d.AntivirusSignatureVersion

    Add-Result "Microsoft Defender" "Signature age" INFO `
        $d.AntivirusSignatureAge

    Add-Result "Microsoft Defender" "Quick scan age" INFO `
        $d.QuickScanAge

    Add-Result "Microsoft Defender" "Full scan age" INFO `
        $d.FullScanAge

    Add-Result "Microsoft Defender" "NIS enabled" INFO `
        $d.NISEnabled

    Add-Result "Microsoft Defender" "NIS signature version" INFO `
        $d.NISSignatureVersion
}

# ============================================================
# DEFENDER PREFERENCES
# ============================================================

Run-Check "Microsoft Defender" "Defender preferences" {

    $p = Get-MpPreference

    $properties = @(
        "DisableRealtimeMonitoring",
        "DisableBehaviorMonitoring",
        "DisableIOAVProtection",
        "DisableScriptScanning",
        "DisableArchiveScanning",
        "DisableEmailScanning",
        "DisableRemovableDriveScanning",
        "DisableBlockAtFirstSeen",
        "PUAProtection",
        "CloudBlockLevel",
        "CloudExtendedTimeout",
        "MAPSReporting",
        "SubmitSamplesConsent",
        "EnableNetworkProtection",
        "EnableControlledFolderAccess",
        "AttackSurfaceReductionRules_Actions",
        "AttackSurfaceReductionRules_Ids"
    )

    foreach ($prop in $properties) {
        $value = $p.$prop

        Add-Result "Microsoft Defender" `
            "Preference: $prop" `
            INFO `
            ($value -join ", ")
    }
}

# ============================================================
# DEFENDER EXCLUSIONS
# ============================================================

Run-Check "Microsoft Defender" "Exclusions" {

    $p = Get-MpPreference

    foreach ($x in $p.ExclusionPath) {
        Add-Result "Microsoft Defender" `
            "Excluded path" `
            WARNING `
            $x `
            "Review whether this exclusion is necessary."
    }

    foreach ($x in $p.ExclusionProcess) {
        Add-Result "Microsoft Defender" `
            "Excluded process" `
            WARNING `
            $x
    }

    foreach ($x in $p.ExclusionExtension) {
        Add-Result "Microsoft Defender" `
            "Excluded extension" `
            WARNING `
            $x
    }
}

# ============================================================
# DEFENDER ASR
# ============================================================

Run-Check "Defender ASR" "Attack Surface Reduction" {

    $p = Get-MpPreference

    $ids = $p.AttackSurfaceReductionRules_Ids
    $actions = $p.AttackSurfaceReductionRules_Actions

    if ($ids) {
        for ($i = 0; $i -lt $ids.Count; $i++) {

            $action = if ($i -lt $actions.Count) {
                $actions[$i]
            }
            else {
                "Unknown"
            }

            Add-Result "Defender ASR" `
                "ASR rule $($ids[$i])" `
                INFO `
                "Action=$action"
        }
    }
    else {
        Add-Result "Defender ASR" `
            "ASR rules configured" `
            WARNING `
            "No ASR rules detected"
    }
}

# ============================================================
# CONTROLLED FOLDER ACCESS
# ============================================================

Run-Check "Defender" "Controlled Folder Access" {

    $p = Get-MpPreference

    switch ($p.EnableControlledFolderAccess) {
        0 {
            Add-Result "Defender" "Controlled Folder Access" WARNING "Disabled"
        }
        1 {
            Add-Result "Defender" "Controlled Folder Access" PASS "Enabled"
        }
        2 {
            Add-Result "Defender" "Controlled Folder Access" INFO "Audit mode"
        }
        default {
            Add-Result "Defender" "Controlled Folder Access" INFO $p.EnableControlledFolderAccess
        }
    }
}

# ============================================================
# FIREWALL
# ============================================================

Run-Check "Firewall" "Firewall profiles" {

    $profiles = Get-NetFirewallProfile

    foreach ($profile in $profiles) {

        $state = if ($profile.Enabled) {"PASS"} else {"FAIL"}

        Add-Result "Firewall" `
            "$($profile.Name) firewall" `
            $state `
            "Enabled=$($profile.Enabled); DefaultInbound=$($profile.DefaultInboundAction); DefaultOutbound=$($profile.DefaultOutboundAction)" `
            "Firewall should normally be enabled."
    }
}

Run-Check "Firewall" "Firewall rules" {

    $rules = Get-NetFirewallRule

    $enabled = $rules | Where-Object Enabled -eq "True"
    $inbound = $enabled | Where-Object Direction -eq "Inbound"
    $allowInbound = $inbound | Where-Object Action -eq "Allow"

    Add-Result "Firewall" "Total firewall rules" INFO $rules.Count
    Add-Result "Firewall" "Enabled firewall rules" INFO $enabled.Count
    Add-Result "Firewall" "Enabled inbound rules" INFO $inbound.Count
    Add-Result "Firewall" "Inbound Allow rules" WARNING $allowInbound.Count

    $allowInbound |
        Select-Object DisplayName, Name, Profile, Direction, Action, Enabled |
        Export-Csv "$OutputRoot\Data\Firewall-Inbound-Allow.csv" -NoTypeInformation -Encoding UTF8
}

# ============================================================
# UAC
# ============================================================

Run-Check "UAC" "User Account Control" {

    $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    $enableLUA = Get-RegValueSafe $path "EnableLUA"
    $consent = Get-RegValueSafe $path "ConsentPromptBehaviorAdmin"
    $secureDesktop = Get-RegValueSafe $path "PromptOnSecureDesktop"

    Add-Result "UAC" "EnableLUA" `
        ($(if ($enableLUA -eq 1) {"PASS"} else {"FAIL"})) `
        $enableLUA

    Add-Result "UAC" "Admin consent behavior" INFO $consent

    Add-Result "UAC" "Secure desktop" `
        ($(if ($secureDesktop -eq 1) {"PASS"} else {"WARNING"})) `
        $secureDesktop
}

# ============================================================
# VBS / HVCI / CREDENTIAL GUARD
# ============================================================

Run-Check "Virtualization Security" "Device Guard" {

    $dg = Get-CimInstance `
        -Namespace root\Microsoft\Windows\DeviceGuard `
        -ClassName Win32_DeviceGuard

    if ($dg) {

        Add-Result "Virtualization Security" `
            "Virtualization Based Security status" `
            INFO `
            $dg.VirtualizationBasedSecurityStatus

        Add-Result "Virtualization Security" `
            "Security Services Configured" `
            INFO `
            ($dg.SecurityServicesConfigured -join ", ")

        Add-Result "Virtualization Security" `
            "Security Services Running" `
            INFO `
            ($dg.SecurityServicesRunning -join ", ")

        Add-Result "Virtualization Security" `
            "Code Integrity Policy Enforcement" `
            INFO `
            $dg.CodeIntegrityPolicyEnforcementStatus

        Add-Result "Virtualization Security" `
            "User Mode Code Integrity" `
            INFO `
            $dg.UsermodeCodeIntegrityPolicyEnforcementStatus
    }
}

Run-Check "Virtualization Security" "Registry configuration" {

    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"

    $enableVBS = Get-RegValueSafe $path "EnableVirtualizationBasedSecurity"
    $requirePlatform = Get-RegValueSafe $path "RequirePlatformSecurityFeatures"

    Add-Result "Virtualization Security" `
        "EnableVirtualizationBasedSecurity" INFO $enableVBS

    Add-Result "Virtualization Security" `
        "RequirePlatformSecurityFeatures" INFO $requirePlatform
}

Run-Check "LSA" "LSA protection" {

    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

    $runAsPPL = Get-RegValueSafe $path "RunAsPPL"

    if ($runAsPPL -eq 1 -or $runAsPPL -eq 2) {
        Add-Result "LSA" "RunAsPPL" PASS $runAsPPL
    }
    else {
        Add-Result "LSA" "RunAsPPL" WARNING `
            $runAsPPL `
            "Consider enabling LSA protection where compatible."
    }
}

# ============================================================
# EXPLOIT PROTECTION
# ============================================================

Run-Check "Exploit Protection" "System mitigation configuration" {

    try {
        $xml = Get-ProcessMitigation -System

        $xml | Out-String |
            Set-Content "$OutputRoot\Data\ExploitProtection-System.txt"

        Add-Result "Exploit Protection" `
            "System mitigation policy" `
            INFO `
            "Exported to Data\ExploitProtection-System.txt"
    }
    catch {
        Add-Result "Exploit Protection" `
            "System mitigation policy" `
            WARNING `
            "Unable to query"
    }
}

# ============================================================
# LOCAL USERS
# ============================================================

Run-Check "Accounts" "Local users" {

    $users = Get-LocalUser

    foreach ($u in $users) {

        $status = if ($u.Enabled) {"INFO"} else {"PASS"}

        Add-Result "Accounts" `
            "Local user: $($u.Name)" `
            $status `
            "Enabled=$($u.Enabled); PasswordRequired=$($u.PasswordRequired); LastLogon=$($u.LastLogon)"
    }
}

Run-Check "Accounts" "Administrator account" {

    $admin = Get-LocalUser |
        Where-Object {
            $_.SID.Value -match "-500$"
        }

    if ($admin) {

        Add-Result "Accounts" `
            "Built-in Administrator" `
            ($(if (-not $admin.Enabled) {"PASS"} else {"WARNING"})) `
            "Enabled=$($admin.Enabled)"
    }
}

Run-Check "Accounts" "Guest account" {

    $guest = Get-LocalUser |
        Where-Object {
            $_.SID.Value -match "-501$"
        }

    if ($guest) {

        Add-Result "Accounts" `
            "Built-in Guest" `
            ($(if (-not $guest.Enabled) {"PASS"} else {"WARNING"})) `
            "Enabled=$($guest.Enabled)"
    }
}

# ============================================================
# ADMINISTRATORS
# ============================================================

Run-Check "Accounts" "Local Administrators" {

    $admins = Get-LocalGroupMember -Group "Administrators"

    foreach ($a in $admins) {
        Add-Result "Accounts" `
            "Local administrator" `
            WARNING `
            "$($a.Name) [$($a.ObjectClass)]"
    }

    $admins |
        Select-Object Name,ObjectClass,PrincipalSource |
        Export-Csv "$OutputRoot\Data\Local-Administrators.csv" `
        -NoTypeInformation -Encoding UTF8
}

# ============================================================
# PASSWORD POLICY
# ============================================================

Run-Check "Password Policy" "Local security policy" {

    $cfg = "$OutputRoot\Data\SecurityPolicy.inf"

    secedit /export /cfg $cfg /quiet | Out-Null

    if (Test-Path $cfg) {

        $content = Get-Content $cfg

        foreach ($line in $content) {

            if ($line -match "^(MinimumPasswordAge|MaximumPasswordAge|MinimumPasswordLength|PasswordComplexity|PasswordHistorySize|LockoutBadCount|ResetLockoutCount|LockoutDuration)\s*=") {

                $parts = $line -split "=",2

                Add-Result "Password Policy" `
                    $parts[0].Trim() `
                    INFO `
                    $parts[1].Trim()
            }
        }
    }
}

# ============================================================
# AUDIT POLICY
# ============================================================

Run-Check "Auditing" "Advanced audit policy" {

    $audit = auditpol /get /category:* 2>&1

    $audit |
        Out-File "$OutputRoot\Data\AuditPolicy.txt" -Encoding UTF8

    Add-Result "Auditing" `
        "Advanced audit policy" `
        INFO `
        "Full output saved to Data\AuditPolicy.txt"
}

# ============================================================
# EVENT LOGS
# ============================================================

Run-Check "Event Logs" "Security log configuration" {

    $log = Get-WinEvent -ListLog Security

    Add-Result "Event Logs" "Security log enabled" `
        ($(if ($log.IsEnabled) {"PASS"} else {"FAIL"})) `
        $log.IsEnabled

    Add-Result "Event Logs" "Security log maximum size" `
        INFO `
        "$([math]::Round($log.MaximumSizeInBytes / 1MB,2)) MB"

    Add-Result "Event Logs" "Security log record count" INFO `
        $log.RecordCount
}

Run-Check "Event Logs" "Important security events" {

    $ids = @{
        "4624" = "Successful logon"
        "4625" = "Failed logon"
        "4672" = "Special privileges assigned"
        "4688" = "Process creation"
        "4697" = "Service installed"
        "4720" = "User account created"
        "4722" = "User account enabled"
        "4728" = "Member added to global security group"
        "4732" = "Member added to local security group"
        "4740" = "Account locked"
        "1102" = "Security audit log cleared"
    }

    foreach ($id in $ids.Keys) {

        $events = Get-WinEvent -FilterHashtable @{
            LogName = "Security"
            Id = [int]$id
            StartTime = (Get-Date).AddDays(-30)
        } -MaxEvents 20

        Add-Result "Event Logs" `
            "Event $id - $($ids[$id])" `
            INFO `
            "$($events.Count) events in last 30 days"
    }
}

# ============================================================
# WINDOWS UPDATE
# ============================================================

Run-Check "Windows Update" "Update services" {

    $services = @(
        "wuauserv",
        "UsoSvc",
        "BITS",
        "WaaSMedicSvc"
    )

    foreach ($name in $services) {

        $s = Get-Service $name

        if ($s) {

            Add-Result "Windows Update" `
                "Service $name" `
                INFO `
                "Status=$($s.Status); StartType=$($s.StartType)"
        }
    }
}

Run-Check "Windows Update" "HotFix history" {

    $hotfix = Get-HotFix |
        Sort-Object InstalledOn -Descending

    $hotfix |
        Select-Object -First 50 |
        Export-Csv "$OutputRoot\Data\HotFixes.csv" `
        -NoTypeInformation -Encoding UTF8

    $latest = $hotfix | Select-Object -First 1

    if ($latest) {
        Add-Result "Windows Update" `
            "Latest installed update" `
            INFO `
            "$($latest.HotFixID) - $($latest.InstalledOn)"
    }
}

# ============================================================
# RDP
# ============================================================

Run-Check "Remote Access" "RDP configuration" {

    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"

    $deny = Get-RegValueSafe $path "fDenyTSConnections"

    if ($deny -eq 1) {
        Add-Result "Remote Access" "RDP" PASS "Disabled"
    }
    else {
        Add-Result "Remote Access" "RDP" WARNING `
            "Enabled" `
            "Ensure RDP is required and restricted."
    }

    $rdpNla = Get-RegValueSafe `
        "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
        "UserAuthentication"

    Add-Result "Remote Access" "RDP NLA" INFO $rdpNla
}

# ============================================================
# WINRM
# ============================================================

Run-Check "Remote Management" "WinRM" {

    $service = Get-Service WinRM

    if ($service) {

        if ($service.Status -eq "Running") {
            Add-Result "Remote Management" `
                "WinRM service" `
                WARNING `
                "Running"
        }
        else {
            Add-Result "Remote Management" `
                "WinRM service" `
                PASS `
                "Not running"
        }
    }

    winrm get winrm/config |
        Out-File "$OutputRoot\Data\WinRM-Config.txt" -Encoding UTF8
}

# ============================================================
# SMB
# ============================================================

Run-Check "SMB" "SMB configuration" {

    $smb = Get-SmbServerConfiguration

    Add-Result "SMB" "SMB1 server" INFO $smb.EnableSMB1Protocol
    Add-Result "SMB" "SMB2/3 server" INFO $smb.EnableSMB2Protocol
    Add-Result "SMB" "SMB signing required" INFO $smb.RequireSecuritySignature
    Add-Result "SMB" "SMB encryption" INFO $smb.EncryptData
}

Run-Check "SMB" "SMB shares" {

    $shares = Get-SmbShare

    foreach ($share in $shares) {

        Add-Result "SMB" `
            "Share $($share.Name)" `
            INFO `
            "Path=$($share.Path); Description=$($share.Description)"
    }

    $shares |
        Select-Object Name,Path,Description,EncryptData,FolderEnumerationMode |
        Export-Csv "$OutputRoot\Data\SMB-Shares.csv" `
        -NoTypeInformation -Encoding UTF8
}

# ============================================================
# NTLM
# ============================================================

Run-Check "Authentication" "NTLM configuration" {

    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

    $lmCompatibility = Get-RegValueSafe `
        $path `
        "LmCompatibilityLevel"

    $restrictAnonymous = Get-RegValueSafe `
        $path `
        "RestrictAnonymous"

    Add-Result "Authentication" `
        "LmCompatibilityLevel" `
        INFO `
        $lmCompatibility

    Add-Result "Authentication" `
        "RestrictAnonymous" `
        INFO `
        $restrictAnonymous
}

# ============================================================
# POWERSHELL
# ============================================================

Run-Check "PowerShell" "PowerShell configuration" {

    Add-Result "PowerShell" `
        "PowerShell version" `
        INFO `
        $PSVersionTable.PSVersion.ToString()

    Add-Result "PowerShell" `
        "ExecutionPolicy CurrentUser" `
        INFO `
        (Get-ExecutionPolicy -Scope CurrentUser)

    Add-Result "PowerShell" `
        "ExecutionPolicy LocalMachine" `
        INFO `
        (Get-ExecutionPolicy -Scope LocalMachine)

    Add-Result "PowerShell" `
        "ExecutionPolicy Process" `
        INFO `
        (Get-ExecutionPolicy -Scope Process)
}

Run-Check "PowerShell" "PowerShell logging" {

    $paths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    )

    foreach ($path in $paths) {

        if (Test-Path $path) {

            $props = Get-ItemProperty $path

            foreach ($p in $props.PSObject.Properties) {

                if ($p.Name -notmatch "^PS") {

                    Add-Result "PowerShell" `
                        $path `
                        INFO `
                        "$($p.Name)=$($p.Value)"
                }
            }
        }
        else {
            Add-Result "PowerShell" `
                $path `
                INFO `
                "Not configured"
        }
    }
}

# ============================================================
# NETWORK PROFILES
# ============================================================

Run-Check "Network" "Network profiles" {

    Get-NetConnectionProfile |
        ForEach-Object {

            Add-Result "Network" `
                "Network $($_.Name)" `
                INFO `
                "Category=$($_.NetworkCategory); IPv4=$($_.IPv4Connectivity); IPv6=$($_.IPv6Connectivity)"
        }
}

# ============================================================
# NETWORK CONFIGURATION
# ============================================================

Run-Check "Network" "IP configuration" {

    Get-NetIPConfiguration |
        ForEach-Object {

            Add-Result "Network" `
                "Interface $($_.InterfaceAlias)" `
                INFO `
                "IPv4=$($_.IPv4Address.IPAddress); Gateway=$($_.IPv4DefaultGateway.NextHop); DNS=$($_.DNSServer.ServerAddresses -join ',')"
        }
}

# ============================================================
# LISTENING PORTS
# ============================================================

Run-Check "Network" "Listening TCP ports" {

    $listeners = Get-NetTCPConnection -State Listen |
        Sort-Object LocalPort

    foreach ($l in $listeners) {

        $process = Get-Process -Id $l.OwningProcess

        Add-Result "Network" `
            "TCP $($l.LocalAddress):$($l.LocalPort)" `
            WARNING `
            "PID=$($l.OwningProcess); Process=$($process.ProcessName)"
    }

    $listeners |
        Select-Object LocalAddress,LocalPort,OwningProcess,State |
        Export-Csv "$OutputRoot\Data\TCP-Listeners.csv" `
        -NoTypeInformation -Encoding UTF8
}

Run-Check "Network" "Listening UDP ports" {

    $listeners = Get-NetUDPEndpoint |
        Sort-Object LocalPort

    foreach ($l in $listeners) {

        $process = Get-Process -Id $l.OwningProcess

        Add-Result "Network" `
            "UDP $($l.LocalAddress):$($l.LocalPort)" `
            INFO `
            "PID=$($l.OwningProcess); Process=$($process.ProcessName)"
    }

    $listeners |
        Select-Object LocalAddress,LocalPort,OwningProcess |
        Export-Csv "$OutputRoot\Data\UDP-Listeners.csv" `
        -NoTypeInformation -Encoding UTF8
}

# ============================================================
# ACTIVE CONNECTIONS
# ============================================================

Run-Check "Network" "Active TCP connections" {

    Get-NetTCPConnection -State Established |
        ForEach-Object {

            $process = Get-Process -Id $_.OwningProcess

            Add-Result "Network" `
                "Established connection" `
                INFO `
                "$($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort) [$($process.ProcessName)]"
        }
}

# ============================================================
# DNS
# ============================================================

Run-Check "Network" "DNS servers" {

    Get-DnsClientServerAddress |
        ForEach-Object {

            if ($_.ServerAddresses) {

                Add-Result "Network" `
                    "DNS $($_.InterfaceAlias)" `
                    INFO `
                    ($_.ServerAddresses -join ", ")
            }
        }
}

# ============================================================
# SERVICES
# ============================================================

Run-Check "Services" "Automatic services" {

    $services = Get-CimInstance Win32_Service |
        Where-Object StartMode -eq "Auto"

    $services |
        Select-Object Name,DisplayName,State,StartMode,StartName,PathName |
        Export-Csv "$OutputRoot\Data\Automatic-Services.csv" `
        -NoTypeInformation -Encoding UTF8

    Add-Result "Services" `
        "Automatic services count" `
        INFO `
        $services.Count
}

# ============================================================
# DRIVERS
# ============================================================

Run-Check "Drivers" "Loaded drivers" {

    $drivers = Get-CimInstance Win32_SystemDriver |
        Where-Object State -eq "Running"

    $drivers |
        Select-Object Name,DisplayName,State,StartMode,PathName |
        Export-Csv "$OutputRoot\Data\Loaded-Drivers.csv" `
        -NoTypeInformation -Encoding UTF8

    Add-Result "Drivers" `
        "Loaded kernel/system drivers" `
        INFO `
        $drivers.Count
}

# ============================================================
# STARTUP
# ============================================================

Run-Check "Persistence" "Startup commands" {

    $startup = Get-CimInstance Win32_StartupCommand

    foreach ($s in $startup) {

        Add-Result "Persistence" `
            "Startup: $($s.Name)" `
            WARNING `
            "$($s.Command) [$($s.Location)]"
    }

    $startup |
        Select-Object Name,Command,Location,User |
        Export-Csv "$OutputRoot\Data\Startup-Commands.csv" `
        -NoTypeInformation -Encoding UTF8
}

# ============================================================
# SCHEDULED TASKS
# ============================================================

Run-Check "Persistence" "Scheduled tasks" {

    $tasks = Get-ScheduledTask

    $interesting = $tasks |
        Where-Object {
            $_.State -ne "Disabled"
        }

    Add-Result "Persistence" `
        "Enabled/active scheduled tasks" `
        INFO `
        $interesting.Count

    $interesting |
        Select-Object TaskPath,TaskName,State,Author |
        Export-Csv "$OutputRoot\Data\Scheduled-Tasks.csv" `
        -NoTypeInformation -Encoding UTF8
}

# ============================================================
# APPLOCKER
# ============================================================

Run-Check "Application Control" "AppLocker" {

    $service = Get-Service AppIDSvc

    if ($service) {

        Add-Result "Application Control" `
            "Application Identity service" `
            INFO `
            "Status=$($service.Status); StartType=$($service.StartType)"
    }

    $rules = Get-AppLockerPolicy -Effective

    if ($rules) {

        $rules |
            Out-File "$OutputRoot\Data\AppLocker-Effective.txt" `
            -Encoding UTF8

        Add-Result "Application Control" `
            "AppLocker effective policy" `
            INFO `
            "Exported"
    }
    else {
        Add-Result "Application Control" `
            "AppLocker effective policy" `
            INFO `
            "Not configured"
    }
}

# ============================================================
# WDAC / CODE INTEGRITY
# ============================================================

Run-Check "Application Control" "Code Integrity" {

    $log = "Microsoft-Windows-CodeIntegrity/Operational"

    try {

        $events = Get-WinEvent `
            -LogName $log `
            -MaxEvents 20

        Add-Result "Application Control" `
            "Code Integrity operational log" `
            INFO `
            "$($events.Count) recent events"
    }
    catch {
        Add-Result "Application Control" `
            "Code Integrity operational log" `
            INFO `
            "Unavailable"
    }
}

# ============================================================
# CERTIFICATES
# ============================================================

Run-Check "Certificates" "Local machine certificates" {

    $stores = @(
        "Cert:\LocalMachine\My",
        "Cert:\LocalMachine\Root",
        "Cert:\LocalMachine\CA"
    )

    foreach ($store in $stores) {

        if (Test-Path $store) {

            $certs = Get-ChildItem $store

            Add-Result "Certificates" `
                $store `
                INFO `
                "$($certs.Count) certificates"

            foreach ($cert in $certs | Where-Object NotAfter -lt (Get-Date).AddDays(30)) {

                Add-Result "Certificates" `
                    "Certificate expiring soon" `
                    WARNING `
                    "$($cert.Subject); Expiry=$($cert.NotAfter)"
            }
        }
    }
}

# ============================================================
# USB
# ============================================================

Run-Check "Devices" "USB devices" {

    Get-PnpDevice |
        Where-Object {
            $_.InstanceId -like "USB*"
        } |
        ForEach-Object {

            Add-Result "Devices" `
                "USB device" `
                INFO `
                "$($_.FriendlyName); Status=$($_.Status)"
        }
}

# ============================================================
# WINDOWS SECURITY CENTER
# ============================================================

Run-Check "Windows Security" "Security Center" {

    $services = @(
        "SecurityHealthService",
        "wscsvc"
    )

    foreach ($name in $services) {

        $s = Get-Service $name

        if ($s) {

            Add-Result "Windows Security" `
                $name `
                INFO `
                "Status=$($s.Status); StartType=$($s.StartType)"
        }
    }
}

# ============================================================
# SMARTSCREEN
# ============================================================

Run-Check "SmartScreen" "Windows SmartScreen" {

    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost"
    )

    foreach ($path in $paths) {

        if (Test-Path $path) {

            $props = Get-ItemProperty $path

            foreach ($p in $props.PSObject.Properties) {

                if ($p.Name -match "SmartScreen|EnableWebContentEvaluation") {

                    Add-Result "SmartScreen" `
                        $p.Name `
                        INFO `
                        $p.Value
                }
            }
        }
    }
}

# ============================================================
# TLS / SCHANNEL
# ============================================================

Run-Check "TLS" "Schannel configuration" {

    $base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"

    foreach ($protocol in @(
        "SSL 2.0",
        "SSL 3.0",
        "TLS 1.0",
        "TLS 1.1",
        "TLS 1.2",
        "TLS 1.3"
    )) {

        $path = Join-Path $base "Protocols\$protocol"

        if (Test-Path $path) {

            $server = Get-ItemProperty `
                (Join-Path $path "Server")

            $client = Get-ItemProperty `
                (Join-Path $path "Client")

            Add-Result "TLS" `
                "$protocol Server" `
                INFO `
                "Enabled=$($server.Enabled); DisabledByDefault=$($server.DisabledByDefault)"

            Add-Result "TLS" `
                "$protocol Client" `
                INFO `
                "Enabled=$($client.Enabled); DisabledByDefault=$($client.DisabledByDefault)"
        }
        else {
            Add-Result "TLS" `
                "$protocol" `
                INFO `
                "No explicit registry override"
        }
    }
}

# ============================================================
# SMB CLIENT
# ============================================================

Run-Check "SMB" "SMB client configuration" {

    $client = Get-SmbClientConfiguration

    Add-Result "SMB" `
        "Client signing required" `
        INFO `
        $client.RequireSecuritySignature

    Add-Result "SMB" `
        "Client encryption" `
        INFO `
        $client.EnableSecuritySignature
}

# ============================================================
# WINDOWS DEFENDER THREATS
# ============================================================

Run-Check "Microsoft Defender" "Threat history" {

    try {

        $detections = Get-MpThreatDetection

        $detections |
            Select-Object * |
            Export-Csv "$OutputRoot\Data\Defender-ThreatDetections.csv" `
            -NoTypeInformation -Encoding UTF8

        Add-Result "Microsoft Defender" `
            "Threat detections" `
            WARNING `
            "$($detections.Count) detection records"
    }
    catch {}
}

# ============================================================
# WINDOWS DEFENDER SCANS
# ============================================================

Run-Check "Microsoft Defender" "Scan history" {

    try {

        Get-MpThreat |
            Export-Csv "$OutputRoot\Data\Defender-Threats.csv" `
            -NoTypeInformation -Encoding UTF8

        $history = Get-MpThreat

        Add-Result "Microsoft Defender" `
            "Current Defender threats" `
            INFO `
            $history.Count
    }
    catch {}
}

# ============================================================
# SECURITY REGISTRY CHECKS
# ============================================================

Run-Check "Registry Security" "Important security registry values" {

    $checks = @(
        @{
            Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            Name="LmCompatibilityLevel"
        },
        @{
            Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            Name="RunAsPPL"
        },
        @{
            Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            Name="RestrictAnonymous"
        },
        @{
            Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            Name="LimitBlankPasswordUse"
        },
        @{
            Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
            Name="fDenyTSConnections"
        },
        @{
            Path="HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
            Name="EnableVirtualizationBasedSecurity"
        },
        @{
            Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Name="EnableLUA"
        }
    )

    foreach ($check in $checks) {

        $value = Get-RegValueSafe `
            -Path $check.Path `
            -Name $check.Name

        Add-Result "Registry Security" `
            "$($check.Name)" `
            INFO `
            "$value [$($check.Path)]"
    }
}

# ============================================================
# WINDOWS FIREWALL SERVICE
# ============================================================

Run-Check "Firewall" "MpsSvc service" {

    $service = Get-Service MpsSvc

    if ($service) {

        Add-Result "Firewall" `
            "Windows Defender Firewall service" `
            ($(if ($service.Status -eq "Running") {"PASS"} else {"FAIL"})) `
            "Status=$($service.Status); StartType=$($service.StartType)"
    }
}

# ============================================================
# SECURITY SERVICES
# ============================================================

Run-Check "Security Services" "Security-related services" {

    $services = @(
        "WinDefend",
        "WdNisSvc",
        "SecurityHealthService",
        "MpsSvc",
        "wscsvc",
        "BITS",
        "wuauserv",
        "EventLog",
        "AppIDSvc",
        "LanmanServer",
        "LanmanWorkstation",
        "WinRM",
        "TermService"
    )

    foreach ($name in $services) {

        $s = Get-Service $name

        if ($s) {

            $status = "INFO"

            if ($name -in @("WinDefend","MpsSvc","SecurityHealthService","EventLog")) {
                if ($s.Status -eq "Running") {
                    $status = "PASS"
                }
                else {
                    $status = "WARNING"
                }
            }

            Add-Result "Security Services" `
                $name `
                $status `
                "Status=$($s.Status); StartType=$($s.StartType)"
        }
    }
}

# ============================================================
# PROCESS LIST
# ============================================================

Run-Check "Processes" "Running processes" {

    Get-Process |
        Select-Object Name,Id,Path,Company,ProductVersion |
        Export-Csv "$OutputRoot\Data\Running-Processes.csv" `
        -NoTypeInformation -Encoding UTF8

    Add-Result "Processes" `
        "Running processes" `
        INFO `
        (Get-Process).Count
}

# ============================================================
# INSTALLED SOFTWARE
# ============================================================

Run-Check "Software" "Installed software" {

    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $software = foreach ($path in $paths) {
        Get-ItemProperty $path |
            Where-Object DisplayName
    }

    $software |
        Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation |
        Sort-Object DisplayName -Unique |
        Export-Csv "$OutputRoot\Data\Installed-Software.csv" `
        -NoTypeInformation -Encoding UTF8

    Add-Result "Software" `
        "Installed applications" `
        INFO `
        (($software | Select-Object DisplayName -Unique).Count)
}

# ============================================================
# WINDOWS OPTIONAL FEATURES
# ============================================================

Run-Check "Windows Features" "Security-related optional features" {

    $features = Get-WindowsOptionalFeature -Online

    $interesting = $features |
        Where-Object {
            $_.FeatureName -match `
            "Hyper-V|Sandbox|Containers|VirtualMachinePlatform|Microsoft-Windows-Subsystem-Linux|SMB1|Telnet|TFTP|IIS"
        }

    foreach ($f in $interesting) {

        $status = if ($f.State -eq "Enabled") {
            "INFO"
        }
        else {
            "INFO"
        }

        Add-Result "Windows Features" `
            $f.FeatureName `
            $status `
            $f.State
    }

    $interesting |
        Export-Csv "$OutputRoot\Data\Security-Related-Features.csv" `
        -NoTypeInformation -Encoding UTF8
}

# ============================================================
# HYPER-V
# ============================================================

Run-Check "Virtualization" "Hyper-V" {

    $feature = Get-WindowsOptionalFeature `
        -Online `
        -FeatureName Microsoft-Hyper-V-All

    if ($feature) {

        Add-Result "Virtualization" `
            "Hyper-V" `
            INFO `
            $feature.State
    }
}

# ============================================================
# WINDOWS SANDBOX
# ============================================================

Run-Check "Isolation" "Windows Sandbox" {

    $feature = Get-WindowsOptionalFeature `
        -Online `
        -FeatureName Containers-DisposableClientVM

    if ($feature) {

        Add-Result "Isolation" `
            "Windows Sandbox" `
            INFO `
            $feature.State
    }
}

# ============================================================
# SYSTEM FILE INTEGRITY
# ============================================================

Run-Check "System Integrity" "System file checker status" {

    Add-Result "System Integrity" `
        "SFC" `
        INFO `
        "Run separately for repair/audit: sfc /verifyonly"
}

Run-Check "System Integrity" "DISM component store" {

    Add-Result "System Integrity" `
        "DISM" `
        INFO `
        "Run separately if required: DISM /Online /Cleanup-Image /ScanHealth"
}

# ============================================================
# POWERSHELL HISTORY
# ============================================================

Run-Check "PowerShell" "PowerShell history file" {

    $historyPath = (Get-PSReadLineOption).HistorySavePath

    if (Test-Path $historyPath) {

        $size = (Get-Item $historyPath).Length

        Add-Result "PowerShell" `
            "PSReadLine history" `
            INFO `
            "$historyPath; Size=$size bytes"
    }
}

# ============================================================
# ENVIRONMENT
# ============================================================

Run-Check "Environment" "PATH configuration" {

    Add-Result "Environment" `
        "Machine PATH" `
        INFO `
        [Environment]::GetEnvironmentVariable("Path","Machine")

    Add-Result "Environment" `
        "User PATH" `
        INFO `
        [Environment]::GetEnvironmentVariable("Path","User")
}

# ============================================================
# ADMINISTRATIVE SHARES
# ============================================================

Run-Check "SMB" "Administrative shares" {

    $shares = Get-SmbShare |
        Where-Object {
            $_.Name -match "^[A-Z]\$$|^ADMIN\$|^IPC\$"
        }

    foreach ($share in $shares) {

        Add-Result "SMB" `
            "Administrative share $($share.Name)" `
            INFO `
            $share.Path
    }
}

# ============================================================
# NETWORK DISCOVERY
# ============================================================

Run-Check "Network" "Network discovery services" {

    $services = @(
        "FDResPub",
        "fdPHost",
        "SSDPSRV",
        "upnphost"
    )

    foreach ($name in $services) {

        $s = Get-Service $name

        if ($s) {

            Add-Result "Network" `
                $name `
                INFO `
                "Status=$($s.Status); StartType=$($s.StartType)"
        }
    }
}

# ============================================================
# PRINT SPOOLER
# ============================================================

Run-Check "Services" "Print Spooler" {

    $s = Get-Service Spooler

    if ($s) {

        if ($s.Status -eq "Running") {
            Add-Result "Services" `
                "Print Spooler" `
                WARNING `
                "Running" `
                "If printing is not required, consider disabling the service."
        }
        else {
            Add-Result "Services" `
                "Print Spooler" `
                PASS `
                "Not running"
        }
    }
}

# ============================================================
# REMOTE REGISTRY
# ============================================================

Run-Check "Remote Access" "Remote Registry" {

    $s = Get-Service RemoteRegistry

    if ($s) {

        if ($s.Status -eq "Running") {
            Add-Result "Remote Access" `
                "Remote Registry" `
                WARNING `
                "Running"
        }
        else {
            Add-Result "Remote Access" `
                "Remote Registry" `
                PASS `
                "Not running"
        }
    }
}

# ============================================================
# TELNET / TFTP
# ============================================================

Run-Check "Legacy Protocols" "Legacy services" {

    foreach ($name in @(
        "TlntSvr",
        "TFTP"
    )) {

        $s = Get-Service $name

        if ($s) {

            Add-Result "Legacy Protocols" `
                $name `
                WARNING `
                "Status=$($s.Status)"
        }
    }
}

# ============================================================
# USB STORAGE
# ============================================================

Run-Check "Removable Media" "USB storage devices" {

    Get-Disk |
        Where-Object BusType -eq "USB" |
        ForEach-Object {

            Add-Result "Removable Media" `
                "USB disk" `
                INFO `
                "Number=$($_.Number); FriendlyName=$($_.FriendlyName); Size=$([math]::Round($_.Size/1GB,2))GB; Health=$($_.HealthStatus)"
        }
}

# ============================================================
# DEFENDER NETWORK PROTECTION
# ============================================================

Run-Check "Defender" "Network Protection" {

    $p = Get-MpPreference

    switch ($p.EnableNetworkProtection) {
        0 {
            Add-Result "Defender" "Network Protection" WARNING "Disabled"
        }
        1 {
            Add-Result "Defender" "Network Protection" PASS "Enabled"
        }
        2 {
            Add-Result "Defender" "Network Protection" INFO "Audit mode"
        }
        default {
            Add-Result "Defender" "Network Protection" INFO $p.EnableNetworkProtection
        }
    }
}

# ============================================================
# FINALIZACJA
# ============================================================

Write-Host ""
Write-Host "Generowanie raportów..." -ForegroundColor Cyan

# CSV
$Results |
    Export-Csv $ReportCsv `
    -NoTypeInformation `
    -Encoding UTF8

# JSON
$Results |
    ConvertTo-Json -Depth 5 |
    Set-Content $ReportJson -Encoding UTF8

# TXT
$Results |
    Format-Table -AutoSize |
    Out-String -Width 300 |
    Set-Content $ReportTxt -Encoding UTF8

# ============================================================
# HTML
# ============================================================

$pass = ($Results | Where-Object Status -eq "PASS").Count
$warn = ($Results | Where-Object Status -eq "WARNING").Count
$fail = ($Results | Where-Object Status -eq "FAIL").Count
$info = ($Results | Where-Object Status -eq "INFO").Count
$errorCount = ($Results | Where-Object Status -eq "ERROR").Count

$rows = foreach ($r in $Results) {

    $class = switch ($r.Status) {
        "PASS"    {"pass"}
        "WARNING" {"warning"}
        "FAIL"    {"fail"}
        "ERROR"   {"error"}
        default   {"info"}
    }

    $value = [System.Web.HttpUtility]::HtmlEncode([string]$r.Value)
    $rec = [System.Web.HttpUtility]::HtmlEncode([string]$r.Recommendation)

@"
<tr class="$class">
<td>$($r.Category)</td>
<td>$($r.Check)</td>
<td><strong>$($r.Status)</strong></td>
<td>$value</td>
<td>$rec</td>
</tr>
"@
}

$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Windows 11 Security Audit - $Computer</title>

<style>

body {
    font-family: Segoe UI, Arial, sans-serif;
    background:#111827;
    color:#e5e7eb;
    margin:30px;
}

h1 {
    color:#60a5fa;
}

.summary {
    display:flex;
    gap:15px;
    margin:20px 0;
}

.card {
    padding:20px;
    border-radius:10px;
    min-width:120px;
    text-align:center;
    font-size:18px;
}

.pass {
    background:#064e3b;
    color:#a7f3d0;
}

.warning {
    background:#78350f;
    color:#fde68a;
}

.fail {
    background:#7f1d1d;
    color:#fecaca;
}

.error {
    background:#581c87;
    color:#e9d5ff;
}

.info {
    background:#1f2937;
    color:#d1d5db;
}

table {
    width:100%;
    border-collapse:collapse;
    margin-top:20px;
    font-size:13px;
}

th {
    background:#1e3a8a;
    color:white;
    padding:10px;
    text-align:left;
    position:sticky;
    top:0;
}

td {
    border-bottom:1px solid #374151;
    padding:8px;
    vertical-align:top;
}

tr.pass td:first-child {
    border-left:5px solid #10b981;
}

tr.warning td:first-child {
    border-left:5px solid #f59e0b;
}

tr.fail td:first-child {
    border-left:5px solid #ef4444;
}

tr.error td:first-child {
    border-left:5px solid #a855f7;
}

tr.info td:first-child {
    border-left:5px solid #6b7280;
}

small {
    color:#9ca3af;
}

</style>
</head>

<body>

<h1>Windows 11 Security Audit</h1>

<p>
<strong>Computer:</strong> $Computer<br>
<strong>Date:</strong> $(Get-Date)<br>
<strong>PowerShell:</strong> $($PSVersionTable.PSVersion)
</p>

<div class="summary">

<div class="card pass">
PASS<br>
<strong>$pass</strong>
</div>

<div class="card warning">
WARNING<br>
<strong>$warn</strong>
</div>

<div class="card fail">
FAIL<br>
<strong>$fail</strong>
</div>

<div class="card info">
INFO<br>
<strong>$info</strong>
</div>

<div class="card error">
ERROR<br>
<strong>$errorCount</strong>
</div>

</div>

<table>

<thead>
<tr>
<th>Category</th>
<th>Check</th>
<th>Status</th>
<th>Value</th>
<th>Recommendation</th>
</tr>
</thead>

<tbody>

$($rows -join "`n")

</tbody>

</table>

</body>
</html>
"@

$html |
    Set-Content $ReportHtml -Encoding UTF8

# ============================================================
# PODSUMOWANIE
# ============================================================

Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " AUDYT ZAKOŃCZONY" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "PASS:    $pass" -ForegroundColor Green
Write-Host "WARNING: $warn" -ForegroundColor Yellow
Write-Host "FAIL:    $fail" -ForegroundColor Red
Write-Host "INFO:    $info" -ForegroundColor Gray
Write-Host "ERROR:   $errorCount" -ForegroundColor Magenta

Write-Host ""
Write-Host "Raport HTML:"
Write-Host $ReportHtml -ForegroundColor Cyan

Write-Host ""
Write-Host "Raport CSV:"
Write-Host $ReportCsv -ForegroundColor Cyan

Write-Host ""
Write-Host "Dane szczegółowe:"
Write-Host "$OutputRoot\Data" -ForegroundColor Cyan

# Otwórz raport HTML
try {
    Start-Process $ReportHtml
}
catch {}
