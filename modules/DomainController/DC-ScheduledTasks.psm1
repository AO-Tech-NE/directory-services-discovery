<#
.SYNOPSIS
Domain Controller scheduled task discovery.

.DESCRIPTION
Read-only inventory of scheduled tasks with focus on:
- Failed executions (LastTaskResult != 0) where available
- Tasks not running as SYSTEM
- Tasks likely not Microsoft-owned (noise-aware: task path + author)

Collector behavior:
- Enumerates tasks even if Get-ScheduledTaskInfo fails.
- Always returns schema-stable output.
- Records errors with counts so failures are obvious in summaries.

STATUS
Implemented (local validated; DC validation pending)

AUTHOR
Cheri Leichleiter
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-DSDScheduledTaskInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName
    )

    $capturedAtUtc = (Get-Date).ToUniversalTime().ToString("o")

    $result = [pscustomobject]@{
        schema_version  = "0.1"
        computer_name   = $ComputerName
        captured_at_utc = $capturedAtUtc

        telemetry = [pscustomobject]@{
            enumerated_tasks = 0
            info_success     = 0
            info_failed      = 0
            errors_count     = 0
        }

        findings = [pscustomobject]@{
            failed_tasks        = @()
            non_system_tasks    = @()
            non_microsoft_tasks = @()
        }

        counts = [pscustomobject]@{
            total_tasks         = 0
            failed_tasks        = 0
            non_system_tasks    = 0
            non_microsoft_tasks = 0
        }

        errors = @()
        status = "ok"
    }

    try {
        # Enumerate tasks
        if ($ComputerName -ieq $env:COMPUTERNAME -or $ComputerName -ieq "localhost") {
            $tasks = @(Get-ScheduledTask)
        } else {
            $tasks = @(Get-ScheduledTask -CimSession $ComputerName)
        }

        $result.telemetry.enumerated_tasks = $tasks.Count
        $result.counts.total_tasks = $tasks.Count

        $items = @()

        foreach ($task in $tasks) {
            # Always capture basic metadata even if task info fails
            $runAs = $null
            try { $runAs = $task.Principal.UserId } catch { $runAs = $null }

            $author = $null
            try { $author = $task.Author } catch { $author = $null }

            $actions = @()
            try {
                $actions = @($task.Actions | ForEach-Object {
                    if ($null -ne $_.Execute -and $_.Execute -ne "") { $_.Execute } else { $null }
                }) | Where-Object { $_ -ne $null }
            } catch {
                $actions = @()
            }

            $lastRun = $null
            $lastResult = $null
            $state = $null

            try {
                $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath
                $state = $info.State
                $lastRun = $info.LastRunTime
                $lastResult = [int]$info.LastTaskResult
                $result.telemetry.info_success++
            } catch {
                $result.telemetry.info_failed++
                $result.errors += [pscustomobject]@{
                    stage      = "task-info"
                    task       = "$($task.TaskPath)$($task.TaskName)"
                    error_type = $_.Exception.GetType().FullName
                    error      = $_.Exception.Message
                }
            }

            $items += [pscustomobject]@{
                name           = $task.TaskName
                path           = $task.TaskPath
                state          = $state
                last_run_time  = $lastRun
                last_result    = $lastResult
                author         = $author
                run_as_user    = $runAs
                run_level      = $task.Principal.RunLevel
                actions        = ($actions -join "; ")
            }
        }

        $result.telemetry.errors_count = @($result.errors).Count

        # Filters
        $failed = @($items | Where-Object { $null -ne $_.last_result -and $_.last_result -ne 0 })
        $result.findings.failed_tasks = $failed
        $result.counts.failed_tasks = $failed.Count

        $nonSystem = @($items | Where-Object {
            $_.run_as_user -and
            $_.run_as_user -notmatch '^(SYSTEM|NT AUTHORITY\\SYSTEM)$'
        })
        $result.findings.non_system_tasks = $nonSystem
        $result.counts.non_system_tasks = $nonSystem.Count

        $nonMicrosoft = @($items | Where-Object {
            ($_.path -notmatch '^\\Microsoft\\') -and
            (
                -not $_.author -or
                ($_.author -notmatch 'Microsoft')
            )
        })
        $result.findings.non_microsoft_tasks = $nonMicrosoft
        $result.counts.non_microsoft_tasks = $nonMicrosoft.Count

        $result.status = "ok"
        return $result
    }
    catch {
        $result.status = "skipped_or_failed"
        $result.errors += [pscustomobject]@{
            stage      = "collector"
            error_type = $_.Exception.GetType().FullName
            error      = $_.Exception.Message
        }
        $result.telemetry.errors_count = @($result.errors).Count
        return $result
    }
}

Export-ModuleMember -Function Get-DSDScheduledTaskInventory
