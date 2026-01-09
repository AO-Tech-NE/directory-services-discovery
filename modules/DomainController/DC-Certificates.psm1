<#
.SYNOPSIS
Domain Controller certificate store discovery (read-only).

.DESCRIPTION
Collects certificate metadata from LocalMachine trust stores using the PowerShell
Cert:\ provider and identifies:
- Expired certificates
- Weak RSA keys (below a minimum bit threshold)

This module performs NO remediation.

REMOTE SUPPORT
Local-only for baseline. Remote collection will be added only after validation
(on real DCs) via WinRM/Invoke-Command or agent-based execution.

OUTPUT
Returns a plain PowerShell object containing only primitive/serializable fields.

STATUS
Implemented (baseline, local validated pending).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-DSDCertificateInventory {
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

    if (-not ($ComputerName -ieq $env:COMPUTERNAME -or $ComputerName -ieq "localhost")) {
        throw "Remote certificate store discovery is not implemented yet. Run locally on the target system."
    }

    $capturedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
    $nowUtc = (Get-Date).ToUniversalTime()

    $allCerts = New-Object System.Collections.Generic.List[object]
    $storeErrors = New-Object System.Collections.Generic.List[object]

    foreach ($storeName in $Stores) {
        $path = "Cert:\LocalMachine\$storeName"

        try {
            # Get-ChildItem returns X509Certificate2 objects
            $certs = Get-ChildItem -Path $path -ErrorAction Stop

            foreach ($cert in $certs) {
                $notBeforeUtc = $cert.NotBefore.ToUniversalTime()
                $notAfterUtc  = $cert.NotAfter.ToUniversalTime()

                $isExpired = ($notAfterUtc -lt $nowUtc)

                $rsaBits = $null
                $isWeakRsa = $false

                # RSA key strength detection (RSA only, by design)
                try {
                    $rsa = $cert.GetRSAPublicKey()
                    if ($null -ne $rsa) {
                        $rsaBits = $rsa.KeySize
                        if ($rsaBits -lt $RsaMinBits) {
                            $isWeakRsa = $true
                        }
                    }
                } catch {
                    $rsaBits = $null
                    $isWeakRsa = $false
                }

                $allCerts.Add([pscustomobject]@{
                    store                 = $storeName
                    thumbprint            = $cert.Thumbprint
                    subject               = $cert.Subject
                    issuer                = $cert.Issuer
                    serial_number         = $cert.SerialNumber
                    not_before_utc        = $notBeforeUtc.ToString("o")
                    not_after_utc         = $notAfterUtc.ToString("o")
                    signature_algorithm   = $cert.SignatureAlgorithm.FriendlyName
                    public_key_algorithm  = $cert.PublicKey.Oid.FriendlyName
                    rsa_key_bits          = $rsaBits
                    is_expired            = [bool]$isExpired
                    is_weak_rsa            = [bool]$isWeakRsa
                })
            }
        } catch {
            $storeErrors.Add([pscustomobject]@{
                store = $storeName
                path  = $path
                error_type = $_.Exception.GetType().FullName
                error = $_.Exception.Message
            })
        }
    }

    $expired = $allCerts | Where-Object { $_.is_expired -eq $true } | Sort-Object store, subject
    $weakRsa = $allCerts | Where-Object { $_.is_weak_rsa -eq $true } | Sort-Object store, subject

    $status = "ok"
    if (@($storeErrors).Count -gt 0 -and @($allCerts).Count -eq 0) {
        $status = "skipped_or_failed"
    } elseif (@($storeErrors).Count -gt 0) {
        $status = "partial"
    }

    [pscustomobject]@{
        schema_version  = "0.1"
        computer_name   = $ComputerName
        captured_at_utc = $capturedAtUtc
        stores_scanned  = @($Stores)
        thresholds      = [pscustomobject]@{
            rsa_min_bits = $RsaMinBits
        }
        findings = [pscustomobject]@{
            expired_certificates   = @($expired)
            weak_rsa_certificates  = @($weakRsa)
        }
        counts = [pscustomobject]@{
            total_certificates     = @($allCerts).Count
            expired_certificates   = @($expired).Count
            weak_rsa_certificates  = @($weakRsa).Count
        }
        errors = @($storeErrors)
        status = $status
    }
}

Export-ModuleMember -Function Get-DSDCertificateInventory
