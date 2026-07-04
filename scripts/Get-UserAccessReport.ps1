#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.DirectoryManagement

<#
.SYNOPSIS
    Generates an access report for one or all users in Microsoft Entra ID.

.DESCRIPTION
    Queries Microsoft Graph to report on user role assignments and group
    memberships. Can target a single user by UPN or generate a full tenant
    access report. Outputs to console and exports a timestamped CSV to logs/.

    Supports -WhatIf for safe pre-flight testing.

.PARAMETER UserPrincipalName
    Optional. UPN of a specific user to report on.
    If omitted, reports on all users in the tenant.

.PARAMETER IncludeDisabled
    Switch. Include disabled accounts in the report.
    Disabled accounts are excluded by default.

.EXAMPLE
    .\Get-UserAccessReport.ps1

.EXAMPLE
    .\Get-UserAccessReport.ps1 -UserPrincipalName "john.doe@spwiringgmail.onmicrosoft.com"

.EXAMPLE
    .\Get-UserAccessReport.ps1 -IncludeDisabled -WhatIf

.NOTES
    Author:      Christopher J. Williams
    GitHub:      github.com/cjwilliamstech
    Repo:        entra-iam-scripts
    Requires:    Microsoft.Graph PowerShell SDK
    Permissions: User.Read.All, Directory.Read.All, RoleManagement.Read.Directory
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter()]
    [string]$UserPrincipalName,

    [Parameter()]
    [switch]$IncludeDisabled
)

#region --- Configuration ---
$ErrorActionPreference = "Stop"
$ScriptName            = "Get-UserAccessReport"
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

#region --- Helper: Get User Access Data ---
function Get-UserAccess {
    param (
        [Microsoft.Graph.PowerShell.Models.MicrosoftGraphUser]$User
    )

    # Get group memberships directly via dedicated cmdlet
    $GroupObjects = Get-MgUserMemberOfAsGroup -UserId $User.Id -All -ErrorAction SilentlyContinue
    $Groups = $GroupObjects | ForEach-Object { $_.DisplayName }

    # Get directory role assignments directly via dedicated cmdlet
    $RoleObjects = Get-MgUserMemberOfAsDirectoryRole -UserId $User.Id -All -ErrorAction SilentlyContinue
    $Roles = $RoleObjects | ForEach-Object { $_.DisplayName }

    [PSCustomObject]@{
        DisplayName       = $User.DisplayName
        UserPrincipalName = $User.UserPrincipalName
        AccountEnabled    = $User.AccountEnabled
        UserType          = $User.UserType
        Department        = $User.Department
        JobTitle          = $User.JobTitle
        ObjectId          = $User.Id
        GroupCount        = $Groups.Count
        Groups            = ($Groups -join " | ")
        RoleCount         = $Roles.Count
        Roles             = if ($Roles.Count -gt 0) { $Roles -join " | " } else { "None" }
    }
}
#endregion

#region --- Pre-flight ---
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

Write-Log "Script started by: $env:USER"

if ($UserPrincipalName) {
    Write-Log "Mode: Single user report for $UserPrincipalName"
} else {
    Write-Log "Mode: Full tenant access report"
}

Write-Log "Include disabled accounts: $IncludeDisabled"
#endregion

#region --- Retrieve Users ---
try {
    if ($UserPrincipalName) {
        # Single user mode
        Write-Log "Looking up user: $UserPrincipalName"
        $Users = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" `
                 -Property "Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,Department,JobTitle" `
                 -ErrorAction Stop

        if (-not $Users) {
            Write-Log "User $UserPrincipalName not found in directory." -Level ERROR
            exit 1
        }
    } else {
        # All users mode
        Write-Log "Retrieving all users from tenant..."
        $Users = Get-MgUser -All `
                 -Property "Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,Department,JobTitle" `
                 -ErrorAction Stop

        Write-Log "Total users retrieved: $($Users.Count)"

        # Filter disabled unless flag set
        if (-not $IncludeDisabled) {
            $Users = $Users | Where-Object { $_.AccountEnabled -eq $true }
            Write-Log "Active users after filtering: $($Users.Count)"
        }
    }
} catch {
    Write-Log "Failed to retrieve users. Error: $_" -Level ERROR
    throw
}
#endregion

#region --- Build Report ---
Write-Log "Building access report..."
$Report = @()
$Counter = 0

foreach ($User in $Users) {
    $Counter++
    Write-Progress -Activity "Retrieving access data" `
                   -Status "$Counter of $($Users.Count) — $($User.DisplayName)" `
                   -PercentComplete (($Counter / $Users.Count) * 100)

    try {
        $AccessData = Get-UserAccess -User $User
        $Report += $AccessData
        Write-Log "Processed: $($User.UserPrincipalName) | Groups: $($AccessData.GroupCount) | Roles: $($AccessData.RoleCount)"
    } catch {
        Write-Log "Failed to retrieve access data for $($User.UserPrincipalName). Error: $_" -Level WARN
    }
}

Write-Progress -Completed -Activity "Retrieving access data"
#endregion

#region --- Console Output ---
Write-Host "`n--- User Access Report ---" -ForegroundColor Yellow
Write-Host "Generated  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "Total Users: $($Report.Count)"
Write-Host "--------------------------`n"

if ($UserPrincipalName) {
    # Detailed single user view
    $User = $Report[0]
    Write-Host "Display Name : $($User.DisplayName)" -ForegroundColor Cyan
    Write-Host "UPN          : $($User.UserPrincipalName)"
    Write-Host "Account      : $(if ($User.AccountEnabled) { 'Enabled' } else { 'Disabled' })"
    Write-Host "User Type    : $($User.UserType)"
    Write-Host "Department   : $($User.Department)"
    Write-Host "Job Title    : $($User.JobTitle)"
    Write-Host "Object ID    : $($User.ObjectId)"
    Write-Host "`nGroup Memberships ($($User.GroupCount)):" -ForegroundColor Yellow
    if ($User.GroupCount -gt 0) {
        $User.Groups -split " \| " | ForEach-Object { Write-Host "  - $_" }
    } else {
        Write-Host "  None"
    }
    Write-Host "`nDirectory Roles ($($User.RoleCount)):" -ForegroundColor Yellow
    if ($User.Roles -ne "None") {
        $User.Roles -split " \| " | ForEach-Object { Write-Host "  - $_" }
    } else {
        Write-Host "  None"
    }
} else {
    # Summary table view for all users
    $Report | Format-Table DisplayName, UserPrincipalName, AccountEnabled, GroupCount, RoleCount, Roles -AutoSize
}
#endregion

#region --- CSV Export ---
if ($PSCmdlet.ShouldProcess($CsvFile, "Export access report to CSV")) {
    $Report | Export-Csv -Path $CsvFile -NoTypeInformation -Encoding UTF8
    Write-Log "CSV report exported to: $CsvFile"
}
#endregion

#region --- Summary ---
Write-Host "`n--- Report Complete ---" -ForegroundColor Green
Write-Host "Users reported : $($Report.Count)"
Write-Host "CSV exported to: $CsvFile"
Write-Host "Log written to : $LogFile"
Write-Host "----------------------`n"

Write-Log "Script completed. $($Report.Count) user(s) reported."
#endregion