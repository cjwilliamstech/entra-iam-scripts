#Requires -Modules Microsoft.Graph.Identity.SignIns

<#
.SYNOPSIS
    Generates a report of all Conditional Access policies in Microsoft Entra ID.

.DESCRIPTION
    Queries Microsoft Graph for all Conditional Access policies and produces
    both a summary table and a detailed per-policy breakdown including users,
    groups, applications, conditions, and grant controls.

    Output can be directed to console, CSV, or both at runtime.
    Supports -WhatIf for safe pre-flight testing.

.PARAMETER OutputFormat
    Controls where the report is sent.
    Options: Both (default), ConsoleOnly, CSVOnly

.PARAMETER PolicyState
    Filter policies by state.
    Options: All (default), Enabled, Disabled, EnabledForReportingButNotEnforced

.EXAMPLE
    .\Get-ConditionalAccessReport.ps1

.EXAMPLE
    .\Get-ConditionalAccessReport.ps1 -OutputFormat CSVOnly

.EXAMPLE
    .\Get-ConditionalAccessReport.ps1 -PolicyState Enabled -OutputFormat ConsoleOnly

.EXAMPLE
    .\Get-ConditionalAccessReport.ps1 -WhatIf

.NOTES
    Author:      Christopher J. Williams
    GitHub:      github.com/cjwilliamstech
    Repo:        entra-iam-scripts
    Requires:    Microsoft.Graph PowerShell SDK
    Permissions: Policy.Read.All, Directory.Read.All
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter()]
    [ValidateSet("Both", "ConsoleOnly", "CSVOnly")]
    [string]$OutputFormat = "Both",

    [Parameter()]
    [ValidateSet("All", "Enabled", "Disabled", "EnabledForReportingButNotEnforced")]
    [string]$PolicyState = "All"
)

#region --- Configuration ---
$ErrorActionPreference = "Stop"
$ScriptName            = "Get-ConditionalAccessReport"
$LogDir                = Join-Path $PSScriptRoot "..\logs"
$LogFile               = Join-Path $LogDir "$ScriptName-$(Get-Date -Format 'yyyy-MM-dd').log"
$CsvFile               = Join-Path $LogDir "$ScriptName-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').csv"
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

#region --- Helper: Resolve Display Names ---
function Resolve-UserOrGroupName {
    param ([string]$Id)

    # Handle well-known special values
    if ($Id -eq "All") { return "All Users" }
    if ($Id -eq "GuestsOrExternalUsers") { return "Guests or External Users" }
    if ($Id -eq "None") { return "None" }

    try {
        $user = Get-MgUser -UserId $Id -Property "DisplayName" -ErrorAction Stop
        return $user.DisplayName
    } catch {
        try {
            $group = Get-MgGroup -GroupId $Id -Property "DisplayName" -ErrorAction Stop
            return $group.DisplayName
        } catch {
            # Object not found — flag it as a potential misconfiguration
            return "[Unresolved: $Id]"
        }
    }
}

function Resolve-AppName {
    param ([string]$AppId)
    try {
        $sp = Get-MgServicePrincipal -Filter "appId eq '$AppId'" -Property "DisplayName" -ErrorAction Stop
        if ($sp) { return $sp.DisplayName }
        return $AppId
    } catch {
        return $AppId
    }
}
#endregion

#region --- Pre-flight ---
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

Write-Log "Script started by: $env:USER"
Write-Log "Output format: $OutputFormat | Policy state filter: $PolicyState"
#endregion

#region --- Retrieve Policies ---
Write-Log "Retrieving Conditional Access policies..."

try {
    $AllPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
    Write-Log "Total policies retrieved: $($AllPolicies.Count)"
} catch {
    Write-Log "Failed to retrieve Conditional Access policies. Error: $_" -Level ERROR
    throw
}

# Apply state filter
if ($PolicyState -ne "All") {
    $AllPolicies = $AllPolicies | Where-Object { $_.State -eq $PolicyState }
    Write-Log "Policies after state filter ($PolicyState): $($AllPolicies.Count)"
}

if ($AllPolicies.Count -eq 0) {
    Write-Log "No policies found matching the criteria. Exiting." -Level WARN
    exit 0
}
#endregion

#region --- Build Report ---
Write-Log "Building policy report..."
$SummaryReport  = @()
$DetailedReport = @()

foreach ($Policy in $AllPolicies) {

    # --- Resolve included users ---
    $IncludedUsers = "None"
    if ($Policy.Conditions.Users.IncludeUsers) {
        if ($Policy.Conditions.Users.IncludeUsers -contains "All") {
            $IncludedUsers = "All Users"
        } else {
            $IncludedUsers = ($Policy.Conditions.Users.IncludeUsers | ForEach-Object {
                Resolve-UserOrGroupName -Id $_
            }) -join " | "
        }
    }

    # --- Resolve excluded users ---
    $ExcludedUsers = "None"
    if ($Policy.Conditions.Users.ExcludeUsers) {
        $ExcludedUsers = ($Policy.Conditions.Users.ExcludeUsers | ForEach-Object {
            Resolve-UserOrGroupName -Id $_
        }) -join " | "
    }

    # --- Resolve included groups ---
    $IncludedGroups = "None"
    if ($Policy.Conditions.Users.IncludeGroups) {
        $IncludedGroups = ($Policy.Conditions.Users.IncludeGroups | ForEach-Object {
            Resolve-UserOrGroupName -Id $_
        }) -join " | "
    }

    # --- Resolve excluded groups ---
    $ExcludedGroups = "None"
    if ($Policy.Conditions.Users.ExcludeGroups) {
        $ExcludedGroups = ($Policy.Conditions.Users.ExcludeGroups | ForEach-Object {
            Resolve-UserOrGroupName -Id $_
        }) -join " | "
    }

    # --- Resolve applications ---
    $IncludedApps = "None"
    if ($Policy.Conditions.Applications.IncludeApplications) {
        if ($Policy.Conditions.Applications.IncludeApplications -contains "All") {
            $IncludedApps = "All Applications"
        } else {
            $IncludedApps = ($Policy.Conditions.Applications.IncludeApplications | ForEach-Object {
                Resolve-AppName -AppId $_
            }) -join " | "
        }
    }

    $ExcludedApps = "None"
    if ($Policy.Conditions.Applications.ExcludeApplications) {
        $ExcludedApps = ($Policy.Conditions.Applications.ExcludeApplications | ForEach-Object {
            Resolve-AppName -AppId $_
        }) -join " | "
    }

    # --- Resolve grant controls ---
    $GrantControls = "None"
    if ($Policy.GrantControls.BuiltInControls) {
        $GrantControls = $Policy.GrantControls.BuiltInControls -join " | "
        if ($Policy.GrantControls.Operator) {
            $GrantControls = "[$($Policy.GrantControls.Operator)] $GrantControls"
        }
    }

    # --- Resolve platforms ---
    $Platforms = "Any"
    if ($Policy.Conditions.Platforms.IncludePlatforms) {
        $Platforms = $Policy.Conditions.Platforms.IncludePlatforms -join " | "
    }

    # --- Resolve locations ---
    $Locations = "Any"
    if ($Policy.Conditions.Locations.IncludeLocations) {
        $Locations = $Policy.Conditions.Locations.IncludeLocations -join " | "
    }

    # --- Resolve sign-in risk levels ---
    $SignInRisk = "None"
    if ($Policy.Conditions.SignInRiskLevels) {
        $SignInRisk = $Policy.Conditions.SignInRiskLevels -join " | "
    }

    # --- Resolve user risk levels ---
    $UserRisk = "None"
    if ($Policy.Conditions.UserRiskLevels) {
        $UserRisk = $Policy.Conditions.UserRiskLevels -join " | "
    }

    # --- Resolve session controls ---
    $SessionControls = "None"
    $SessionList = @()
    if ($Policy.SessionControls.SignInFrequency.IsEnabled) {
        $SessionList += "SignInFrequency: $($Policy.SessionControls.SignInFrequency.Value) $($Policy.SessionControls.SignInFrequency.Type)"
    }
    if ($Policy.SessionControls.PersistentBrowser.IsEnabled) {
        $SessionList += "PersistentBrowser: $($Policy.SessionControls.PersistentBrowser.Mode)"
    }
    if ($Policy.SessionControls.CloudAppSecurity.IsEnabled) {
        $SessionList += "CloudAppSecurity: $($Policy.SessionControls.CloudAppSecurity.CloudAppSecurityType)"
    }
    if ($SessionList.Count -gt 0) { $SessionControls = $SessionList -join " | " }

    # --- Build summary object ---
    $Summary = [PSCustomObject]@{
        PolicyName      = $Policy.DisplayName
        State           = $Policy.State
        IncludedUsers   = $IncludedUsers
        IncludedGroups  = $IncludedGroups
        IncludedApps    = $IncludedApps
        GrantControls   = $GrantControls
        PolicyId        = $Policy.Id
    }

    # --- Build detailed object ---
    $Detail = [PSCustomObject]@{
        PolicyName        = $Policy.DisplayName
        PolicyId          = $Policy.Id
        State             = $Policy.State
        CreatedDateTime   = $Policy.CreatedDateTime
        ModifiedDateTime  = $Policy.ModifiedDateTime
        IncludedUsers     = $IncludedUsers
        ExcludedUsers     = $ExcludedUsers
        IncludedGroups    = $IncludedGroups
        ExcludedGroups    = $ExcludedGroups
        IncludedApps      = $IncludedApps
        ExcludedApps      = $ExcludedApps
        Platforms         = $Platforms
        Locations         = $Locations
        SignInRiskLevels  = $SignInRisk
        UserRiskLevels    = $UserRisk
        GrantControls     = $GrantControls
        SessionControls   = $SessionControls
    }

    $SummaryReport  += $Summary
    $DetailedReport += $Detail

    Write-Log "Processed policy: $($Policy.DisplayName) | State: $($Policy.State)"
}
#endregion

#region --- Console Output ---
if ($OutputFormat -in "Both", "ConsoleOnly") {

    Write-Host "`n--- Conditional Access Policy Report ---" -ForegroundColor Yellow
    Write-Host "Generated    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host "Total Policies: $($AllPolicies.Count)"
    Write-Host "State Filter  : $PolicyState"
    Write-Host "----------------------------------------`n"

    # Summary table
    Write-Host "=== Policy Summary ===" -ForegroundColor Green
    $SummaryReport | Format-Table PolicyName, State, IncludedUsers, IncludedApps, GrantControls -AutoSize

    # Detailed per-policy view
    Write-Host "`n=== Detailed Policy Breakdown ===" -ForegroundColor Green

    foreach ($Detail in $DetailedReport) {
        Write-Host "`n--- $($Detail.PolicyName) ---" -ForegroundColor Cyan
        Write-Host "Policy ID        : $($Detail.PolicyId)"
        Write-Host "State            : $($Detail.State)"
        Write-Host "Created          : $($Detail.CreatedDateTime)"
        Write-Host "Last Modified    : $($Detail.ModifiedDateTime)"
        Write-Host "`nUsers & Groups:"
        Write-Host "  Included Users : $($Detail.IncludedUsers)"
        Write-Host "  Excluded Users : $($Detail.ExcludedUsers)"
        Write-Host "  Included Groups: $($Detail.IncludedGroups)"
        Write-Host "  Excluded Groups: $($Detail.ExcludedGroups)"
        Write-Host "`nApplications:"
        Write-Host "  Included Apps  : $($Detail.IncludedApps)"
        Write-Host "  Excluded Apps  : $($Detail.ExcludedApps)"
        Write-Host "`nConditions:"
        Write-Host "  Platforms      : $($Detail.Platforms)"
        Write-Host "  Locations      : $($Detail.Locations)"
        Write-Host "  Sign-in Risk   : $($Detail.SignInRiskLevels)"
        Write-Host "  User Risk      : $($Detail.UserRiskLevels)"
        Write-Host "`nControls:"
        Write-Host "  Grant Controls : $($Detail.GrantControls)"
        Write-Host "  Session Controls: $($Detail.SessionControls)"
    }
}
#endregion

#region --- CSV Export ---
if ($OutputFormat -in "Both", "CSVOnly") {
    if ($PSCmdlet.ShouldProcess($CsvFile, "Export Conditional Access report to CSV")) {
        $DetailedReport | Export-Csv -Path $CsvFile -NoTypeInformation -Encoding UTF8
        Write-Log "CSV report exported to: $CsvFile"
    }
}
#endregion

#region --- Summary ---
Write-Host "`n--- Report Complete ---" -ForegroundColor Green
Write-Host "Policies reported : $($AllPolicies.Count)"
if ($OutputFormat -in "Both", "CSVOnly") {
    Write-Host "CSV exported to   : $CsvFile"
}
Write-Host "Log written to    : $LogFile"
Write-Host "----------------------`n"

Write-Log "Script completed. $($AllPolicies.Count) Conditional Access policy/policies reported."
#endregion