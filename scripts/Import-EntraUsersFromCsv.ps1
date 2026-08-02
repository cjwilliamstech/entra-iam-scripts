#Requires -Modules Microsoft.Graph.Users

<#
.SYNOPSIS
    Bulk provisions Entra ID users from a CSV file via Microsoft Graph.

.DESCRIPTION
    Reads a CSV file containing user details and provisions each user in
    Microsoft Entra ID. Skips duplicate UPNs, handles spaces in names,
    generates secure temporary passwords, and logs all actions to logs/.

    Supports -WhatIf for safe pre-flight testing.

.PARAMETER CsvPath
    Full path to the CSV file containing user data.
    Required columns: FirstName, LastName, Department, JobTitle
    Optional columns: UsageLocation (defaults to US if omitted)

.PARAMETER SkipDuplicates
    Switch. Automatically skip existing users without prompting.
    Default behavior is to prompt for each duplicate.

.EXAMPLE
    .\Import-EntraUsersFromCsv.ps1 -CsvPath "../samples/bulk-users-template.csv"

.EXAMPLE
    .\Import-EntraUsersFromCsv.ps1 -CsvPath "../samples/bulk-users-template.csv" -SkipDuplicates

.EXAMPLE
    .\Import-EntraUsersFromCsv.ps1 -CsvPath "../samples/bulk-users-template.csv" -WhatIf

.NOTES
    Author:      Christopher J. Williams
    GitHub:      github.com/cjwilliamstech/entra-iam-scripts
    Repo:        entra-iam-scripts
    Requires:    Microsoft.Graph PowerShell SDK
    Permissions: User.ReadWrite.All, Directory.ReadWrite.All

    CSV Format:
    FirstName,LastName,Department,JobTitle,UsageLocation
    John,Doe,IT,Help Desk Analyst,US
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory)]
    [string]$CsvPath,

    [Parameter()]
    [switch]$SkipDuplicates
)

#region --- Configuration ---
$ErrorActionPreference = "Stop"
$ScriptName            = "Import-EntraUsersFromCsv"
$LogDir                = Join-Path $PSScriptRoot "..\logs"
$LogFile               = Join-Path $LogDir "$ScriptName-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').log"
$ResultsCsvFile        = Join-Path $LogDir "$ScriptName-Results-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').csv"
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
Write-Log "CSV path: $CsvPath"
Write-Log "Skip duplicates: $SkipDuplicates"

# Validate CSV exists
if (-not (Test-Path $CsvPath)) {
    Write-Log "CSV file not found at path: $CsvPath" -Level ERROR
    exit 1
}

# Import and validate CSV
try {
    $Users = Import-Csv -Path $CsvPath -ErrorAction Stop
    Write-Log "CSV loaded successfully. Total rows: $($Users.Count)"
} catch {
    Write-Log "Failed to import CSV. Error: $_" -Level ERROR
    exit 1
}

# Validate required columns exist
$RequiredColumns = @("FirstName", "LastName", "Department", "JobTitle")
$CsvColumns      = $Users[0].PSObject.Properties.Name

foreach ($Col in $RequiredColumns) {
    if ($Col -notin $CsvColumns) {
        Write-Log "Missing required column: $Col" -Level ERROR
        exit 1
    }
}

Write-Log "CSV validation passed. All required columns present."

# Resolve tenant domain
$DomainName = (Get-MgOrganization).VerifiedDomains |
              Where-Object { $_.IsDefault } |
              Select-Object -ExpandProperty Name

Write-Log "Tenant domain resolved: $DomainName"
#endregion

#region --- Bulk Provisioning ---
$Results  = @()
$Created  = 0
$Skipped  = 0
$Failed   = 0
$Counter  = 0

Write-Host "`n--- Bulk User Import ---" -ForegroundColor Yellow
Write-Host "CSV File  : $CsvPath"
Write-Host "Total rows: $($Users.Count)"
Write-Host "------------------------`n"

foreach ($User in $Users) {
    $Counter++

    # Build user attributes
    $FirstName    = $User.FirstName.Trim()
    $LastName     = $User.LastName.Trim()
    $Department   = $User.Department.Trim()
    $JobTitle     = $User.JobTitle.Trim()
    $UsageLocation = if ($User.UsageLocation) { $User.UsageLocation.Trim() } else { "US" }

    $DisplayName  = "$FirstName $LastName"
    $MailNickname = "$($FirstName.ToLower()).$($LastName.ToLower())" -replace '\s+', ''
    $UPN          = "$MailNickname@$DomainName"

    Write-Progress -Activity "Bulk User Import" `
                   -Status "Processing $Counter of $($Users.Count) — $DisplayName" `
                   -PercentComplete (($Counter / $Users.Count) * 100)

    Write-Log "Processing row $Counter of $($Users.Count): $DisplayName | UPN: $UPN"

    # Check for duplicate
    $ExistingUser = Get-MgUser -Filter "userPrincipalName eq '$UPN'" -ErrorAction SilentlyContinue

    if ($ExistingUser) {
        if ($SkipDuplicates) {
            Write-Log "Duplicate found — skipping: $UPN" -Level WARN
            $Results += [PSCustomObject]@{
                DisplayName = $DisplayName
                UPN         = $UPN
                Department  = $Department
                JobTitle    = $JobTitle
                Status      = "Skipped - Already Exists"
                TempPassword = "N/A"
            }
            $Skipped++
            continue
        } else {
            Write-Host "`nUser already exists: $UPN" -ForegroundColor Yellow
            $choice = Read-Host "  [S]kip / [O]verwrite"
            if ($choice.ToUpper() -ne "O") {
                Write-Log "Duplicate skipped by operator: $UPN" -Level WARN
                $Results += [PSCustomObject]@{
                    DisplayName  = $DisplayName
                    UPN          = $UPN
                    Department   = $Department
                    JobTitle     = $JobTitle
                    Status       = "Skipped - Duplicate"
                    TempPassword = "N/A"
                }
                $Skipped++
                continue
            }
        }
    }

    # Generate password
    $Password = -join ((33..126) | Get-Random -Count 16 | ForEach-Object { [char]$_ })

    # Build user params
    $UserParams = @{
        DisplayName       = $DisplayName
        GivenName         = $FirstName
        Surname           = $LastName
        UserPrincipalName = $UPN
        MailNickname      = $MailNickname
        Department        = $Department
        JobTitle          = $JobTitle
        UsageLocation     = $UsageLocation
        AccountEnabled    = $true
        PasswordProfile   = @{
            Password                             = $Password
            ForceChangePasswordNextSignIn        = $true
            ForceChangePasswordNextSignInWithMfa = $false
        }
    }

    # Create or update user
    if ($PSCmdlet.ShouldProcess($UPN, "Create Entra ID user")) {
        try {
            if ($ExistingUser) {
                Update-MgUser -UserId $ExistingUser.Id -BodyParameter $UserParams
                Write-Log "User updated: $UPN"
                $Status = "Updated"
            } else {
                $NewUser = New-MgUser -BodyParameter $UserParams
                Write-Log "User created: $UPN | Object ID: $($NewUser.Id)"
                $Status = "Created"
            }

            $Results += [PSCustomObject]@{
                DisplayName  = $DisplayName
                UPN          = $UPN
                Department   = $Department
                JobTitle     = $JobTitle
                Status       = $Status
                TempPassword = $Password
            }
            $Created++

        } catch {
            Write-Log "Failed to create user $UPN. Error: $_" -Level ERROR
            $Results += [PSCustomObject]@{
                DisplayName  = $DisplayName
                UPN          = $UPN
                Department   = $Department
                JobTitle     = $JobTitle
                Status       = "Failed - $($_.Exception.Message)"
                TempPassword = "N/A"
            }
            $Failed++
        }
    }
}

Write-Progress -Completed -Activity "Bulk User Import"
#endregion

#region --- Results Output ---
Write-Host "`n--- Import Results ---" -ForegroundColor Green
$Results | Format-Table DisplayName, UPN, Status -AutoSize

# Export results to CSV
if ($PSCmdlet.ShouldProcess($ResultsCsvFile, "Export results to CSV")) {
    $Results | Export-Csv -Path $ResultsCsvFile -NoTypeInformation -Encoding UTF8
    Write-Log "Results exported to: $ResultsCsvFile"
}
#endregion

#region --- Summary ---
Write-Host "`n--- Import Summary ---" -ForegroundColor Green
Write-Host "Total processed : $($Users.Count)"
Write-Host "Created         : $Created" -ForegroundColor Green
Write-Host "Skipped         : $Skipped" -ForegroundColor Yellow
Write-Host "Failed          : $Failed" -ForegroundColor Red
Write-Host "Results CSV     : $ResultsCsvFile"
Write-Host "Log file        : $LogFile"
Write-Host "----------------------`n"

Write-Log "Script completed. Created: $Created | Skipped: $Skipped | Failed: $Failed"
#endregion