#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.DirectoryManagement

<#
.SYNOPSIS
    Offboards a user from Microsoft Entra ID via Microsoft Graph.

.DESCRIPTION
    Performs a structured six-step offboarding process:
      1. Disable the account
      2. Revoke all active sessions
      3. Remove group memberships
      4. Remove directory role assignments
      5. Hide from Global Address List
      6. Soft delete or permanent delete with confirmation

    All actions are logged to the logs/ directory. Supports -WhatIf
    for safe pre-flight testing.

.PARAMETER UserPrincipalName
    The UPN of the user to offboard (e.g. john.doe@contoso.onmicrosoft.com)

.EXAMPLE
    .\Remove-EntraUser.ps1 -UserPrincipalName "john.doe@spwiringgmail.onmicrosoft.com"

.EXAMPLE
    .\Remove-EntraUser.ps1 -UserPrincipalName "john.doe@spwiringgmail.onmicrosoft.com" -WhatIf

.NOTES
    Author:      Christopher J. Williams
    GitHub:      github.com/cjwilliamstech
    Repo:        entra-iam-scripts
    Requires:    Microsoft.Graph PowerShell SDK
    Permissions: User.ReadWrite.All, Directory.ReadWrite.All
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory)]
    [string]$UserPrincipalName
)

#region --- Configuration ---
$ErrorActionPreference = "Stop"
$ScriptName            = "Remove-EntraUser"
$LogDir                = Join-Path $PSScriptRoot "..\logs"
$LogFile               = Join-Path $LogDir "$ScriptName-$(Get-Date -Format 'yyyy-MM-dd').log"
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
Write-Log "Target UPN: $UserPrincipalName"

# Verify user exists
Write-Log "Looking up user: $UserPrincipalName"
$User = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" `
        -Property "Id,DisplayName,UserPrincipalName,AccountEnabled,ShowInAddressList" `
        -ErrorAction SilentlyContinue

if (-not $User) {
    Write-Log "User $UserPrincipalName not found in directory. Exiting." -Level ERROR
    exit 1
}

Write-Log "User found: $($User.DisplayName) | Object ID: $($User.Id)"

# Confirm before proceeding
Write-Host "`n--- Offboarding Target ---" -ForegroundColor Yellow
Write-Host "Display Name : $($User.DisplayName)"
Write-Host "UPN          : $($User.UserPrincipalName)"
Write-Host "Object ID    : $($User.Id)"
Write-Host "--------------------------`n"

$confirm = Read-Host "Confirm offboarding of $($User.DisplayName)? [Y]es / [N]o"
if ($confirm.ToUpper() -ne "Y") {
    Write-Log "Offboarding cancelled by operator." -Level WARN
    exit 0
}
#endregion

#region --- Step 1: Disable Account ---
Write-Log "Step 1 of 6 - Disabling account..."
if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Disable account")) {
    try {
        Update-MgUser -UserId $User.Id -BodyParameter @{ accountEnabled = $false }
        Write-Log "Account disabled successfully."
    } catch {
        Write-Log "Failed to disable account. Error: $_" -Level ERROR
        throw
    }
}
#endregion

#region --- Step 2: Revoke Sessions ---
Write-Log "Step 2 of 6 - Revoking all active sessions..."
if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Revoke all active sessions")) {
    try {
        Revoke-MgUserSignInSession -UserId $User.Id
        Write-Log "All active sessions revoked successfully."
    } catch {
        Write-Log "Failed to revoke sessions. Error: $_" -Level ERROR
        throw
    }
}
#endregion

#region --- Step 3: Remove Group Memberships ---
Write-Log "Step 3 of 6 - Removing group memberships..."
if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Remove all group memberships")) {
    try {
        $Groups = Get-MgUserMemberOf -UserId $User.Id -All | 
                  Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' }

        if ($Groups.Count -eq 0) {
            Write-Log "No group memberships found."
        } else {
            foreach ($Group in $Groups) {
                try {
                    Remove-MgGroupMemberByRef -GroupId $Group.Id -DirectoryObjectId $User.Id
                    Write-Log "Removed from group: $($Group.Id)"
                } catch {
                    Write-Log "Could not remove from group $($Group.Id) - may be a dynamic group. Error: $_" -Level WARN
                }
            }
            Write-Log "Group membership removal completed. $($Groups.Count) group(s) processed."
        }
    } catch {
        Write-Log "Failed to retrieve group memberships. Error: $_" -Level ERROR
        throw
    }
}
#endregion

#region --- Step 4: Remove Role Assignments ---
Write-Log "Step 4 of 6 - Removing directory role assignments..."
if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Remove all directory role assignments")) {
    try {
        $Roles = Get-MgUserMemberOf -UserId $User.Id -All | 
                 Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' }

        if ($Roles.Count -eq 0) {
            Write-Log "No directory role assignments found."
        } else {
            foreach ($Role in $Roles) {
                try {
                    Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $Role.Id -DirectoryObjectId $User.Id
                    Write-Log "Removed from role: $($Role.Id)"
                } catch {
                    Write-Log "Could not remove from role $($Role.Id). Error: $_" -Level WARN
                }
            }
            Write-Log "Role assignment removal completed. $($Roles.Count) role(s) processed."
        }
    } catch {
        Write-Log "Failed to retrieve role assignments. Error: $_" -Level ERROR
        throw
    }
}
#endregion

#region --- Step 5: Hide from Global Address List ---
Write-Log "Step 5 of 6 - Hiding user from Global Address List..."
if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Hide from Global Address List")) {
    try {
        Update-MgUser -UserId $User.Id -BodyParameter @{ showInAddressList = $false }
        Write-Log "User hidden from Global Address List successfully."
    } catch {
        Write-Log "Failed to hide user from GAL. Error: $_" -Level ERROR
        throw
    }
}
#endregion

#region --- Step 6: Delete User ---
Write-Log "Step 6 of 6 - Delete user..."

Write-Host "`n--- Deletion Options ---" -ForegroundColor Yellow
Write-Host "[S] Soft delete - user recoverable for 30 days"
Write-Host "[P] Permanent delete - user unrecoverable"
Write-Host "[C] Cancel - leave user disabled"
Write-Host "------------------------`n"

$deleteChoice = Read-Host "Choose deletion type for $($User.DisplayName)"

switch ($deleteChoice.ToUpper()) {
    "S" {
        if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Soft delete user")) {
            try {
                Remove-MgUser -UserId $User.Id
                Write-Log "User soft deleted. Recoverable from deleted users for 30 days."
            } catch {
                Write-Log "Failed to soft delete user. Error: $_" -Level ERROR
                throw
            }
        }
    }
    "P" {
        $finalConfirm = Read-Host "WARNING: This is permanent and cannot be undone. Type 'DELETE' to confirm"
        if ($finalConfirm -eq "DELETE") {
            if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Permanently delete user")) {
                try {
                    Remove-MgUser -UserId $User.Id
                    Remove-MgDirectoryDeletedItem -DirectoryObjectId $User.Id
                    Write-Log "User permanently deleted. This action cannot be undone."
                } catch {
                    Write-Log "Failed to permanently delete user. Error: $_" -Level ERROR
                    throw
                }
            }
        } else {
            Write-Log "Permanent deletion cancelled - confirmation phrase not matched." -Level WARN
            Write-Host "Deletion cancelled. User remains disabled." -ForegroundColor Yellow
        }
    }
    "C" {
        Write-Log "Deletion cancelled by operator. User left in disabled state." -Level WARN
        Write-Host "Offboarding complete. User is disabled but not deleted." -ForegroundColor Yellow
    }
    default {
        Write-Log "Invalid deletion choice entered. User left in disabled state." -Level WARN
        Write-Host "Invalid choice. User left in disabled state." -ForegroundColor Yellow
    }
}
#endregion

#region --- Summary ---
Write-Host "`n--- Offboarding Summary ---" -ForegroundColor Green
Write-Host "User         : $($User.DisplayName)"
Write-Host "UPN          : $($User.UserPrincipalName)"
Write-Host "Completed    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "---------------------------`n"

Write-Log "Offboarding script completed for $UserPrincipalName."
#endregion