<#
.SYNOPSIS
Domain Controller service discovery (read-only).

.DESCRIPTION
Collects service state data from a target system (local or remote) with an
emphasis on actionable operational risk signals:
- Automatic services not running
- Non-standard service identities (optional)
- Summary counts for reporting

This module performs NO remediation and makes NO configuration changes.

OUTPUT
Returns a plain PowerShell object containing only primitive/serializable fields.

STATUS
Implemented (baseline). Validate on real DCs before expanding scope.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-DSDServiceInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName
    )

    # Use CIM for compatibility (works local and remote).
    $services = if ($ComputerName -ieq $env:COMPUTERNAME -or $ComputerName -ieq "localhost") {
        Get-CimInstance -ClassName Win32_Service
    } else {
        Get-CimInstance -ComputerName $ComputerName -ClassName Win32_Service
    }

    # Convert to serializable objects (no CIM instances in output)
    $all = $services | ForEach-Object {
        [pscustomobject]@{
            name         = $_.Name
            display_name = $_.DisplayName
            state        = $_.State
            start_mode   = $_.StartMode
            start_name   = $_.StartName
            exit_code    = $_.ExitCode
            service_type = $_.ServiceType
            path_name    = $_.PathName
        }
    }

    $autoNotRunning = $all |
        Where-Object { $_.start_mode -eq "Auto" -and $_.state -ne "Running" } |
        Sort-Object -Property name

    [pscustomobject]@{
        schema_version = "0.1"
        computer_name  = $ComputerName
        captured_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        automatic_not_running = @($autoNotRunning)
        counts = [pscustomobject]@{
            total_services           = @($all).Count
            automatic_not_running    = @($autoNotRunning).Count
        }
    }
}

Export-ModuleMember -Function Get-DSDServiceInventory
