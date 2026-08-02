#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Groups

<#
.SYNOPSIS
    Provisions a new user in Microsoft Entra ID via Microsoft Graph.

.DESCRIPTION
    Creates a new Entra ID user with standard attributes, assigns a usage
    location, and logs all actions to the logs/ directory. Supports -WhatIf
    for safe pre-flight testing.

.PARAMETER FirstName
    The user's first name.

.PARAMETER LastName
    The user's last name.

.PARAMETER Department
    The user's department.

.PARAMETER JobTitle
    The user's job title.

.PARAMETER UsageLocation
    Two-letter country code for license assignment (default: US).

.EXAMPLE
    .\New-EntraUser.ps1 -FirstName "John" -LastName "Doe" -Department "IT" -JobTitle "Help Desk Analyst"

.EXAMPLE
    .\New-EntraUser.ps1 -FirstName "John" -LastName "Doe" -Department "IT" -JobTitle "Help Desk Analyst" -WhatIf

.NOTES
    Author:      Christopher J. Williams
    GitHub:      github.com/cjwilliamstech
    Repo:        entra-iam-scripts
    Requires:    Microsoft.Graph PowerShell SDK
    Permissions: User.ReadWrite.All, Directory.ReadWrite.All
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter()]
    [string]$FirstName,

    [Parameter()]
    [string]$LastName,

    [Parameter()]
    [string]$Department,

    [Parameter()]
    [string]$JobTitle,

    [Parameter()]
    [string]$UsageLocation = "US"
)

#region --- Configuration ---
$ErrorActionPreference = "Stop"
$ScriptName             = "New-EntraUser"
$LogDir                 = Join-Path $PSScriptRoot "..\logs"
$LogFile                = Join-Path $LogDir "$ScriptName-$(Get-Date -Format 'yyyy-MM-dd').log"
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

# Resolve tenant domain once before the loop
$DomainName = (Get-MgOrganization).VerifiedDomains | 
              Where-Object { $_.IsDefault } | 
              Select-Object -ExpandProperty Name

Write-Log "Tenant domain resolved: $DomainName"
#endregion

#region --- User Provisioning Loop ---
$AnotherUser = $true

while ($AnotherUser) {

    # Prompt for user details if not passed as parameters
    if (-not $FirstName) { $FirstName  = Read-Host "Enter First Name" }
    if (-not $LastName)  { $LastName   = Read-Host "Enter Last Name" }
    if (-not $Department){ $Department = Read-Host "Enter Department" }
    if (-not $JobTitle)  { $JobTitle   = Read-Host "Enter Job Title" }

    Write-Log "Parameters: FirstName=$FirstName, LastName=$LastName, Department=$Department, JobTitle=$JobTitle"

    # Build standard attributes
    $DisplayName  = "$FirstName $LastName"
    $MailNickname = "$($FirstName.ToLower()).$($LastName.ToLower())" -replace '\s+', ''
    $UPN          = "$MailNickname@$DomainName"

    Write-Log "Derived UPN: $UPN"
    Write-Log "Derived DisplayName: $DisplayName"

    #region --- Duplicate Check ---
    Write-Log "Checking for existing user with UPN: $UPN"
    $ExistingUser = Get-MgUser -Filter "userPrincipalName eq '$UPN'" -ErrorAction SilentlyContinue

    if ($ExistingUser) {
        Write-Log "User $UPN already exists in the directory." -Level WARN
        $choice = Read-Host "User already exists. Do you want to skip and exit, or overwrite? [S]kip / [O]verwrite"
        switch ($choice.ToUpper()) {
            "S" {
                Write-Log "User chose to skip. Moving on." -Level WARN
                $FirstName = $null; $LastName = $null; $Department = $null; $JobTitle = $null
                continue
            }
            "O" {
                Write-Log "User chose to overwrite. Existing user will be updated."
            }
            default {
                Write-Log "Invalid choice. Skipping to be safe." -Level WARN
                $FirstName = $null; $LastName = $null; $Department = $null; $JobTitle = $null
                continue
            }
        }
    }
    #endregion

    #region --- Create User ---
    $Password = -join ((33..126) | Get-Random -Count 16 | ForEach-Object { [char]$_ })

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

    if ($PSCmdlet.ShouldProcess($UPN, "Create Entra ID user")) {
        try {
            if ($ExistingUser) {
                Update-MgUser -UserId $ExistingUser.Id -BodyParameter $UserParams
                Write-Log "User $UPN updated successfully."
            } else {
                $NewUser = New-MgUser -BodyParameter $UserParams
                Write-Log "User $UPN created successfully. Object ID: $($NewUser.Id)"
            }

            Write-Log "Temporary password generated. Deliver securely to user."
            Write-Host "`n--- User Provisioning Summary ---" -ForegroundColor Green
            Write-Host "UPN:       $UPN"
            Write-Host "Display:   $DisplayName"
            Write-Host "Dept:      $Department"
            Write-Host "Title:     $JobTitle"
            Write-Host "Temp Pass: $Password"
            Write-Host "---------------------------------`n"

        } catch {
            Write-Log "Failed to create/update user $UPN. Error: $_" -Level ERROR
            throw
        }
    }
    #endregion

    # Reset parameters for next iteration
    $FirstName  = $null
    $LastName   = $null
    $Department = $null
    $JobTitle   = $null

    # Prompt to continue
    $continue = Read-Host "`nWould you like to create another user? [Y]es / [N]o"
    if ($continue.ToUpper() -notin "Y", "YES") {
        $AnotherUser = $false
    }

} # End while loop
#endregion

Write-Log "Script completed successfully. Session ended by operator."