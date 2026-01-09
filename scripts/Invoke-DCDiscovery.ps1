<#
.SYNOPSIS
Domain Controller discovery entrypoint for directory-services-discovery.

.DESCRIPTION
Read-only discovery against a target system. Produces deterministic,
schema-stable JSON outputs suitable for audit, review, and pre-change analysis.

STATUS
Implemented (local validated; DC validation pending)

AUTHOR
Cheri Leichleiter
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Target,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$RunRoot = (Join-Path -Path $PSScriptRoot -ChildPath "..\reports"),

    [switch]$NoWrite
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Update this when you replace the file to prove what ran
$ScriptBuild = "2026-01-09T1930Z"

# --- Repo root + module imports (repo-relative) ---
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Import-Module (Join-Path $RepoRoot "modules\DomainController\DC-Services.psm1") -Force
Import-Module (Join-Path $RepoRoot "modules\DomainController\DC-ScheduledTasks.psm1") -Force

function Ensure-Dir {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Get-UtcIsoNow { (Get-Date).ToUniversalTime().ToString("o") }
function Get-UtcCompact { (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ") }

function Ping-Check {
    param([Parameter(Mandatory = $true)][string]$ComputerName)
    try {
        [pscustomobject]@{
            attempted = $true
            success   = [bool](Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop)
        }
    } catch {
        [pscustomobject]@{
            attempted = $true
            success   = $false
        }
    }
}

function Get-CimSafe {
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][string]$ClassName
    )
    if ($ComputerName -ieq $env:COMPUTERNAME -or $ComputerName -ieq "localhost") {
        return Get-CimInstance -ClassName $ClassName
    }
    return Get-CimInstance -ComputerName $ComputerName -ClassName $ClassName
}

function Read-JsonConfig {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    try { return ($raw | ConvertFrom-Json -ErrorAction Stop) }
    catch { throw "Failed to parse JSON config: $Path`n$($_.Exception.Message)" }
}

function New-CertResultSkeleton {
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][string]$CapturedAtUtc,
        [Parameter(Mandatory = $true)][int]$RsaMinBits,
        [Parameter(Mandatory = $true)][string[]]$Stores
    )

    [pscustomobject]@{
        schema_version  = "0.1"
        computer_name   = $ComputerName
        captured_at_utc = $CapturedAtUtc
        stores_scanned  = @($Stores)
        thresholds      = [pscustomobject]@{ rsa_min_bits = $RsaMinBits }
        findings        = [pscustomobject]@{
            expired_certificates  = @()
            weak_rsa_certificates = @()
        }
        counts          = [pscustomobject]@{
            total_certificates    = 0
            expired_certificates  = 0
            weak_rsa_certificates = 0
        }
        errors          = @()
        status          = "ok"
    }
}

function Get-LocalMachineCertificateInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Mandatory = $false)]
        [ValidateRange(512, 16384)]
        [int]$RsaMinBits = 2048,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Stores = @("Root", "CA")
    )

    $capturedAtUtc = Get-UtcIsoNow
    $result = New-CertResultSkeleton -ComputerName $ComputerName -CapturedAtUtc $capturedAtUtc -RsaMinBits $RsaMinBits -Stores $Stores

    # IMPORTANT: this function must NEVER throw
    try {
        if (-not ($ComputerName -ieq $env:COMPUTERNAME -or $ComputerName -ieq "localhost")) {
            $result.status = "skipped_or_failed"
            $result.errors = @([pscustomobject]@{
                store      = "collector"
                path       = "local-only"
                stage      = "guard"
                error_type = "NotImplemented"
                error      = "Certificate discovery is local-only in baseline. Run locally on the target system."
            })
            return $result
        }

        # Cert:\ provider sanity
        try {
            $null = Get-PSDrive -Name Cert -ErrorAction Stop
        } catch {
            $result.status = "skipped_or_failed"
            $result.errors = @([pscustomobject]@{
                store      = "collector"
                path       = "Cert:\"
                stage      = "psdrive"
                error_type = $_.Exception.GetType().FullName
                error      = $_.Exception.Message
            })
            return $result
        }

        $nowUtc = (Get-Date).ToUniversalTime()
        $allCerts = @()
        $storeErrors = @()

        $RSA_OID = "1.2.840.113549.1.1.1"

        foreach ($storeName in $Stores) {
            $path = "Cert:\LocalMachine\$storeName"
            try {
                $certs = Get-ChildItem -Path $path -ErrorAction Stop

                foreach ($certObj in $certs) {
                    $cert = $null
                    try {
                        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$certObj
                    } catch {
                        $storeErrors += [pscustomobject]@{
                            store      = $storeName
                            path       = $path
                            stage      = "cast"
                            error_type = $_.Exception.GetType().FullName
                            error      = $_.Exception.Message
                        }
                        continue
                    }

                    $notBeforeUtc = $cert.NotBefore.ToUniversalTime()
                    $notAfterUtc  = $cert.NotAfter.ToUniversalTime()
                    $isExpired = ($notAfterUtc -lt $nowUtc)

                    $rsaBits = $null
                    $isWeakRsa = $false

                    try {
                        if ($null -ne $cert.PublicKey -and $null -ne $cert.PublicKey.Oid -and $cert.PublicKey.Oid.Value -eq $RSA_OID) {
                            $rsaBits = $cert.PublicKey.Key.KeySize
                            if ($rsaBits -lt $RsaMinBits) { $isWeakRsa = $true }
                        }
                    } catch {
                        $rsaBits = $null
                        $isWeakRsa = $false
                    }

                    $allCerts += [pscustomobject]@{
                        store                 = $storeName
                        thumbprint            = $cert.Thumbprint
                        subject               = $cert.Subject
                        issuer                = $cert.Issuer
                        serial_number         = $cert.SerialNumber
                        not_before_utc        = $notBeforeUtc.ToString("o")
                        not_after_utc         = $notAfterUtc.ToString("o")
                        signature_algorithm   = $cert.SignatureAlgorithm.FriendlyName
                        public_key_algorithm  = $cert.PublicKey.Oid.FriendlyName
                        public_key_oid        = $cert.PublicKey.Oid.Value
                        rsa_key_bits          = $rsaBits
                        is_expired            = [bool]$isExpired
                        is_weak_rsa            = [bool]$isWeakRsa
                    }
                }
            } catch {
                $storeErrors += [pscustomobject]@{
                    store      = $storeName
                    path       = $path
                    stage      = "enumerate"
                    error_type = $_.Exception.GetType().FullName
                    error      = $_.Exception.Message
                }
            }
        }

        $expired = @($allCerts | Where-Object { $_.is_expired -eq $true } | Sort-Object store, subject)
        $weakRsa = @($allCerts | Where-Object { $_.is_weak_rsa -eq $true } | Sort-Object store, subject)

        $result.findings = [pscustomobject]@{
            expired_certificates  = $expired
            weak_rsa_certificates = $weakRsa
        }

        $result.counts = [pscustomobject]@{
            total_certificates    = @($allCerts).Count
            expired_certificates  = @($expired).Count
            weak_rsa_certificates = @($weakRsa).Count
        }

        $result.errors = @($storeErrors)

        if (@($storeErrors).Count -gt 0 -and @($allCerts).Count -eq 0) {
            $result.status = "skipped_or_failed"
        } elseif (@($storeErrors).Count -gt 0) {
            $result.status = "partial"
        } else {
            $result.status = "ok"
        }

        return $result
    } catch {
        $result.status = "skipped_or_failed"
        $result.errors = @([pscustomobject]@{
            store      = "collector"
            path       = "inline"
            stage      = "outer"
            error_type = $_.Exception.GetType().FullName
            error      = $_.Exception.Message
        })
        return $result
    }
}

# ---- Load thresholds (optional) ----
$RsaMinBits = 2048
try {
    $Thresholds = Read-JsonConfig -Path (Join-Path $RepoRoot "configs\thresholds.json")
    if ($null -ne $Thresholds -and $null -ne $Thresholds.crypto -and $null -ne $Thresholds.crypto.rsa_min_bits) {
        $RsaMinBits = [int]$Thresholds.crypto.rsa_min_bits
    }
} catch {
    $RsaMinBits = 2048
}

# ---- Output dirs ----
Ensure-Dir -Path $RunRoot
$RunRootFull = (Resolve-Path -LiteralPath $RunRoot).Path

$RawDir        = Join-Path $RunRootFull "raw\dc"
$NormalizedDir = Join-Path $RunRootFull "normalized\dc"
$SummariesDir  = Join-Path $RunRootFull "summaries\dc"

Ensure-Dir -Path $RawDir
Ensure-Dir -Path $NormalizedDir
Ensure-Dir -Path $SummariesDir

$CapturedAtUtc = Get-UtcIsoNow
$ts = Get-UtcCompact

$execution = [ordered]@{
    tool             = "directory-services-discovery"
    component        = "dc"
    script           = "Invoke-DCDiscovery.ps1"
    script_build     = $ScriptBuild
    schema_version   = "0.1"
    captured_at_utc  = $CapturedAtUtc
    target           = $Target
    run_root         = $RunRootFull
    raw_output_dir   = $RawDir
    normalized_dir   = $NormalizedDir
    summaries_dir    = $SummariesDir
    computer_context = $env:COMPUTERNAME
    user_context     = $env:USERNAME
}

# ---- Core discovery ----
$ping = Ping-Check -ComputerName $Target
$os = Get-CimSafe -ComputerName $Target -ClassName "Win32_OperatingSystem"
$cs = Get-CimSafe -ComputerName $Target -ClassName "Win32_ComputerSystem"

$boot = [datetime]::Parse($os.LastBootUpTime)
$uptime = (Get-Date) - $boot

$services = Get-DSDServiceInventory -ComputerName $Target
$certificates = Get-LocalMachineCertificateInventory -ComputerName $Target -RsaMinBits $RsaMinBits -Stores @("Root","CA")

# Scheduled tasks (module)
$scheduled_tasks = $null
try {
    $scheduled_tasks = Get-DSDScheduledTaskInventory -ComputerName $Target
} catch {
    $scheduled_tasks = [pscustomobject]@{
        schema_version  = "0.1"
        computer_name   = $Target
        captured_at_utc = $CapturedAtUtc
        findings        = [pscustomobject]@{
            failed_tasks        = @()
            non_system_tasks    = @()
            non_microsoft_tasks = @()
        }
        counts          = [pscustomobject]@{
            total_tasks         = 0
            failed_tasks        = 0
            non_system_tasks    = 0
            non_microsoft_tasks = 0
        }
        errors          = @([pscustomobject]@{
            stage      = "collector"
            error_type = $_.Exception.GetType().FullName
            error      = $_.Exception.Message
        })
        status          = "skipped_or_failed"
    }
}

$payload = [ordered]@{
    schema_version  = "0.1"
    captured_at_utc = $CapturedAtUtc
    target          = $Target

    ping_check = $ping

    identity = [ordered]@{
        dns_host_name               = $cs.DNSHostName
        domain                      = $cs.Domain
        manufacturer                = $cs.Manufacturer
        model                       = $cs.Model
        total_physical_memory_bytes = [int64]$cs.TotalPhysicalMemory
    }

    os = [ordered]@{
        caption          = $os.Caption
        version          = $os.Version
        build_number     = $os.BuildNumber
        install_date_utc = ([datetime]::Parse($os.InstallDate)).ToUniversalTime().ToString("o")
        last_boot_utc    = $boot.ToUniversalTime().ToString("o")
        uptime = [ordered]@{
            days    = [int]([math]::Floor($uptime.TotalDays))
            hours   = [int]([math]::Floor($uptime.TotalHours))
            minutes = [int]([math]::Floor($uptime.TotalMinutes))
        }
    }

    thresholds = [ordered]@{ rsa_min_bits = $RsaMinBits }

    services        = $services
    certificates    = $certificates
    scheduled_tasks = $scheduled_tasks
}

# ---- Write outputs ----
$PayloadPath = Join-Path $RawDir ("dc_{0}.json" -f $ts)
$ExecPath    = Join-Path $RawDir ("dc_execution_{0}.json" -f $ts)

if (-not $NoWrite) {
    ($payload   | ConvertTo-Json -Depth 12) | Out-File -FilePath $PayloadPath -Encoding utf8
    ($execution | ConvertTo-Json -Depth 8 ) | Out-File -FilePath $ExecPath    -Encoding utf8
}

[pscustomobject]@{
    execution      = $execution
    payload        = $payload
    wrote          = (-not $NoWrite)
    payload_path   = $PayloadPath
    execution_path = $ExecPath
}
