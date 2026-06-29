#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Reports

<#
.SYNOPSIS
    Identifies stale Entra ID accounts based on sign-in inactivity.

.DESCRIPTION
    Queries Microsoft Graph for users who have not signed in within a
    configurable number of days. Generates a console report and CSV export,
    then prompts the operator to take action on each stale account:
    disable, skip, or permanently ignore.

    All actions are logged to the logs/ directory. Supports -WhatIf
    for safe pre-flight testing.

.PARAMETER DaysInactive
    Number of days without sign-in activity to qualify as stale.
    Default: 90

.PARAMETER ExcludeGuests
    Switch to exclude guest accounts from the report.

.PARAMETER ExcludeDisabled
    Switch to exclude already-disabled accounts from the report.

.EXAMPLE
    .\Get-StaleAccounts.ps1

.EXAMPLE
    .\Get-StaleAccounts.ps1 -DaysInactive 30 -ExcludeGuests -ExcludeDisabled

.EXAMPLE
    .\Get-StaleAccounts.ps1 -DaysInactive 60 -WhatIf

.NOTES
    Author:      Christopher J. Williams
    GitHub:      github.com/cjwilliamstech
    Repo:        entra-iam-scripts
    Requires:    Microsoft.Graph PowerShell SDK
    Permissions: User.Read.All, AuditLog.Read.All, Directory.Read.All
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter()]
    [int]$DaysInactive = 90,

    [Parameter()]
    [switch]$ExcludeGuests,

    [Parameter()]
    [switch]$ExcludeDisabled
)

#region --- Configuration ---
$ErrorActionPreference = "Stop"
$ScriptName            = "Get-StaleAccounts"
$LogDir                = Join-Path $PSScriptRoot "..\logs"
$LogFile               = Join-Path $LogDir "$ScriptName-$(Get-Date -Format 'yyyy-MM-dd').log"
$CsvFile               = Join-Path $LogDir "$ScriptName-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').csv"
$StaleThreshold        = (Get-Date).AddDays(-$DaysInactive).ToUniversalTime()
#endregion

#region --- Logging ---
function Write-Log {
    param (
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry     = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogFile -Value $entry
    switch ($Level) {
        "INFO"  { Write-Host $entry -ForegroundColor Cyan }
        "WARN"  { Write-Host $entry -ForegroundColor Yellow }
        "ERROR" { Write-Host $entry -ForegroundColor Red }
    }
}
#endregion

#region --- Pre-flight ---
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

Write-Log "Script started by: $env:USER"
Write-Log "Stale threshold: $DaysInactive days (before $(Get-Date $StaleThreshold -Format 'yyyy-MM-dd'))"
Write-Log "Exclude guests: $ExcludeGuests | Exclude disabled: $ExcludeDisabled"
#endregion

#region --- Query Users ---
Write-Log "Querying Entra ID for all users..."

try {
    $AllUsers = Get-MgUser -All `
        -Property "Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,SignInActivity,Department,JobTitle,CreatedDateTime" `
        -ErrorAction Stop

    Write-Log "Total users retrieved: $($AllUsers.Count)"
} catch {
    Write-Log "Failed to retrieve users. Ensure AuditLog.Read.All scope is granted. Error: $_" -Level ERROR
    throw
}
#endregion

#region --- Filter Stale Accounts ---
Write-Log "Filtering for stale accounts..."

$StaleUsers = $AllUsers | Where-Object {
    $user = $_

    # Apply guest filter
    if ($ExcludeGuests -and $user.UserType -eq "Guest") { return $false }

    # Apply disabled filter
    if ($ExcludeDisabled -and $user.AccountEnabled -eq $false) { return $false }

    # Check last sign-in
    $lastSignIn = $user.SignInActivity?.LastSignInDateTime

    if ($null -eq $lastSignIn) {
        # Never signed in — check if account is older than threshold
        $created = $user.CreatedDateTime
        if ($null -eq $created) { return $true }
        return ([datetime]$created -lt $StaleThreshold)
    }

    return ([datetime]$lastSignIn -lt $StaleThreshold)
}

Write-Log "Stale accounts found: $($StaleUsers.Count)"
#endregion

#region --- Build Report ---
if ($StaleUsers.Count -eq 0) {
    Write-Log "No stale accounts found matching the criteria. Exiting."
    exit 0
}

# Build report objects
$Report = $StaleUsers | ForEach-Object {
    $lastSignIn = $_.SignInActivity?.LastSignInDateTime
    $daysSince  = if ($lastSignIn) {
        [int]((Get-Date) - [datetime]$lastSignIn).TotalDays
    } else {
        "Never"
    }

    [PSCustomObject]@{
        DisplayName       = $_.DisplayName
        UserPrincipalName = $_.UserPrincipalName
        AccountEnabled    = $_.AccountEnabled
        UserType          = $_.UserType
        Department        = $_.Department
        JobTitle          = $_.JobTitle
        LastSignIn        = if ($lastSignIn) { 
                                Get-Date $lastSignIn -Format "yyyy-MM-dd" 
                            } else { 
                                "Never" 
                            }
        DaysSinceSignIn   = $daysSince
        ObjectId          = $_.Id
    }
}

# Console output
Write-Host "`n--- Stale Account Report ---" -ForegroundColor Yellow
Write-Host "Threshold  : $DaysInactive days inactive"
Write-Host "Generated  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "Total Found: $($Report.Count)"
Write-Host "----------------------------`n"

$Report | Format-Table DisplayName, UserPrincipalName, AccountEnabled, LastSignIn, DaysSinceSignIn -AutoSize

# CSV export
if ($PSCmdlet.ShouldProcess($CsvFile, "Export stale accounts to CSV")) {
    $Report | Export-Csv -Path $CsvFile -NoTypeInformation -Encoding UTF8
    Write-Log "CSV report exported to: $CsvFile"
}
#endregion

#region --- Action Prompt ---
Write-Host "`n--- Take Action ---" -ForegroundColor Yellow
Write-Host "For each stale account you will be prompted to:"
Write-Host "[D] Disable the account"
Write-Host "[S] Skip - take no action"
Write-Host "[A] Skip all remaining accounts"
Write-Host "-------------------`n"

$SkipAll = $false

foreach ($StaleUser in $Report) {
    if ($SkipAll) { break }

    Write-Host "`nUser      : $($StaleUser.DisplayName)" -ForegroundColor Cyan
    Write-Host "UPN       : $($StaleUser.UserPrincipalName)"
    Write-Host "Last Login: $($StaleUser.LastSignIn) ($($StaleUser.DaysSinceSignIn) days ago)"
    Write-Host "Enabled   : $($StaleUser.AccountEnabled)"

    $action = Read-Host "Action [D]isable / [S]kip / [A]ll skip"

    switch ($action.ToUpper()) {
        "D" {
            if ($PSCmdlet.ShouldProcess($StaleUser.UserPrincipalName, "Disable stale account")) {
                try {
                    Update-MgUser -UserId $StaleUser.ObjectId `
                        -BodyParameter @{ accountEnabled = $false }
                    Write-Log "Disabled stale account: $($StaleUser.UserPrincipalName)"
                    Write-Host "Account disabled." -ForegroundColor Green
                } catch {
                    Write-Log "Failed to disable $($StaleUser.UserPrincipalName). Error: $_" -Level ERROR
                    Write-Host "Failed to disable account. See log for details." -ForegroundColor Red
                }
            }
        }
        "S" {
            Write-Log "Skipped: $($StaleUser.UserPrincipalName)"
            Write-Host "Skipped." -ForegroundColor Yellow
        }
        "A" {
            Write-Log "Operator chose to skip all remaining accounts."
            Write-Host "Skipping all remaining accounts." -ForegroundColor Yellow
            $SkipAll = $true
        }
        default {
            Write-Log "Invalid action entered for $($StaleUser.UserPrincipalName). Skipping." -Level WARN
            Write-Host "Invalid choice. Skipping." -ForegroundColor Yellow
        }
    }
}
#endregion

#region --- Final Summary ---
Write-Host "`n--- Run Complete ---" -ForegroundColor Green
Write-Host "Stale accounts found : $($Report.Count)"
Write-Host "CSV exported to      : $CsvFile"
Write-Host "Log written to       : $LogFile"
Write-Host "--------------------`n"

Write-Log "Script completed. $($Report.Count) stale account(s) identified."
#endregion