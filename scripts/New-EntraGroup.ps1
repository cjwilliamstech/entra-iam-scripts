#Requires -Modules Microsoft.Graph.Groups

<#
.SYNOPSIS
    Creates a new Security or Microsoft 365 group in Microsoft Entra ID.

.DESCRIPTION
    Provisions a new Entra ID group via Microsoft Graph with support for
    both Security and Microsoft 365 group types, static or dynamic membership,
    and optional owner and description assignment.

    Supports -WhatIf for safe pre-flight testing.
    All actions are logged to the logs/ directory.

.PARAMETER GroupName
    Display name of the group to create.

.PARAMETER GroupType
    Type of group to create. Options: Security, M365
    Security = access control group
    M365 = collaboration group with mailbox, Teams, SharePoint

.PARAMETER MembershipType
    How group membership is managed. Options: Static, Dynamic
    Static = members added manually
    Dynamic = members assigned automatically by rule (requires P1/P2)

.PARAMETER Description
    Optional. A description for the group.

.PARAMETER DynamicRule
    Required when MembershipType is Dynamic.
    OData membership rule string.
    Example: "(user.department -eq ""IT"")"

.PARAMETER OwnerUPN
    Optional. UPN of a user to assign as group owner.
    Example: admin@contoso.onmicrosoft.com

.EXAMPLE
    # Create a static security group
    .\New-EntraGroup.ps1 -GroupName "SG-VPN-Users" -GroupType Security -MembershipType Static -Description "Users with VPN access"

.EXAMPLE
    # Create a dynamic security group
    .\New-EntraGroup.ps1 -GroupName "SG-IT-Dynamic" -GroupType Security -MembershipType Dynamic -DynamicRule "(user.department -eq ""IT"")"

.EXAMPLE
    # Create a Microsoft 365 group with an owner
    .\New-EntraGroup.ps1 -GroupName "M365-SecurityTeam" -GroupType M365 -MembershipType Static -OwnerUPN "admin@contoso.onmicrosoft.com"

.EXAMPLE
    # Dry run
    .\New-EntraGroup.ps1 -GroupName "SG-Test" -GroupType Security -MembershipType Static -WhatIf

.NOTES
    Author:      CJ. Williams
    GitHub:      github.com/cjwilliamstech
    Repo:        entra-iam-scripts
    Requires:    Microsoft.Graph PowerShell SDK
    Permissions: Group.ReadWrite.All, Directory.ReadWrite.All
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory)]
    [string]$GroupName,

    # Security = access control, M365 = collaboration with mailbox/Teams/SharePoint
    [Parameter(Mandatory)]
    [ValidateSet("Security", "M365")]
    [string]$GroupType,

    # Static = manual membership, Dynamic = rule-based automatic membership (requires P1/P2)
    [Parameter(Mandatory)]
    [ValidateSet("Static", "Dynamic")]
    [string]$MembershipType,

    [Parameter()]
    [string]$Description = "",

    # OData rule string required when MembershipType is Dynamic
    # Example: "(user.department -eq ""IT"")"
    [Parameter()]
    [string]$DynamicRule,

    # UPN of the user to set as group owner
    [Parameter()]
    [string]$OwnerUPN
)

#region --- Configuration ---
# Set strict error handling and define log file paths
$ErrorActionPreference = "Stop"
$ScriptName            = "New-EntraGroup"
$LogDir                = Join-Path $PSScriptRoot "..\logs"
$LogFile               = Join-Path $LogDir "$ScriptName-$(Get-Date -Format 'yyyy-MM-dd').log"
#endregion

#region --- Logging ---
# Write timestamped entries to both the log file and console with color coding
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
# Create logs directory if it doesn't exist
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

Write-Log "Script started by: $env:USER"
Write-Log "GroupName: $GroupName | GroupType: $GroupType | MembershipType: $MembershipType"

# Validate that DynamicRule is provided when MembershipType is Dynamic
if ($MembershipType -eq "Dynamic" -and -not $DynamicRule) {
    Write-Log "DynamicRule parameter is required when MembershipType is Dynamic." -Level ERROR
    exit 1
}

# Check for duplicate group name before attempting creation
Write-Log "Checking for existing group with name: $GroupName"
$ExistingGroup = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue

if ($ExistingGroup) {
    Write-Log "A group named '$GroupName' already exists. Object ID: $($ExistingGroup.Id)" -Level WARN
    $choice = Read-Host "Group already exists. [S]kip and exit / [C]ontinue with a different name"
    if ($choice.ToUpper() -ne "C") {
        Write-Log "Operator chose to skip. Exiting." -Level WARN
        exit 0
    }
    $GroupName = Read-Host "Enter a new group name"
    Write-Log "New group name entered: $GroupName"
}
#endregion

#region --- Build Group Parameters ---
# Set MailNickname by stripping spaces and special characters from the group name
# MailNickname is required by Graph API even for security groups that don't use email
$MailNickname = $GroupName -replace '[^a-zA-Z0-9]', ''

# Security groups: SecurityEnabled=true, MailEnabled=false, no GroupTypes
# M365 groups: SecurityEnabled=false, MailEnabled=true, GroupTypes=["Unified"]
if ($GroupType -eq "Security") {
    $SecurityEnabled = $true
    $MailEnabled     = $false
    $GroupTypes      = @()
} else {
    # M365 group — "Unified" is the Graph API identifier for Microsoft 365 groups
    $SecurityEnabled = $false
    $MailEnabled     = $true
    $GroupTypes      = @("Unified")
}

# Build the base group parameter hashtable
$GroupParams = @{
    DisplayName     = $GroupName
    Description     = $Description
    MailNickname    = $MailNickname
    SecurityEnabled = $SecurityEnabled
    MailEnabled     = $MailEnabled
    GroupTypes      = $GroupTypes
}

# Add dynamic membership settings if applicable
# MembershipRuleProcessingState must be "On" to activate the rule
if ($MembershipType -eq "Dynamic") {
    $GroupParams["MembershipRule"]                = $DynamicRule
    $GroupParams["MembershipRuleProcessingState"] = "On"
    # Dynamic groups require "DynamicMembership" in GroupTypes
    $GroupParams["GroupTypes"]                    = $GroupTypes + "DynamicMembership"
    Write-Log "Dynamic membership rule: $DynamicRule"
}
#endregion

#region --- Create Group ---
if ($PSCmdlet.ShouldProcess($GroupName, "Create Entra ID group")) {
    try {
        # Create the group in Entra ID via Microsoft Graph
        $NewGroup = New-MgGroup -BodyParameter $GroupParams
        Write-Log "Group created successfully: $GroupName | Object ID: $($NewGroup.Id)"

        # Assign owner if provided
        # Owner must be added as a DirectoryObject reference using the user's Graph URI
        if ($OwnerUPN) {
            Write-Log "Looking up owner: $OwnerUPN"
            $Owner = Get-MgUser -Filter "userPrincipalName eq '$OwnerUPN'" -ErrorAction Stop

            if ($Owner) {
                $OwnerRef = @{
                    "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($Owner.Id)"
                }
                                try {
                    New-MgGroupOwnerByRef -GroupId $NewGroup.Id -BodyParameter $OwnerRef
                    Write-Log "Owner assigned: $OwnerUPN"
                } catch {
                    if ($_.Exception.Message -match "already exist") {
                        Write-Log "Owner $OwnerUPN is already an owner of this group (assigned automatically)." -Level WARN
                    } else {
                        Write-Log "Failed to assign owner $OwnerUPN. Error: $_" -Level ERROR
                        throw
                    }
                }
            } else {
                Write-Log "Owner UPN not found: $OwnerUPN — skipping owner assignment." -Level WARN
            }
        }

        # Display provisioning summary
        Write-Host "`n--- Group Provisioning Summary ---" -ForegroundColor Green
        Write-Host "Name         : $($NewGroup.DisplayName)"
        Write-Host "Object ID    : $($NewGroup.Id)"
        Write-Host "Type         : $GroupType"
        Write-Host "Membership   : $MembershipType"
        Write-Host "Mail Nickname: $MailNickname"
        if ($Description) { Write-Host "Description  : $Description" }
        if ($OwnerUPN)    { Write-Host "Owner        : $OwnerUPN" }
        if ($DynamicRule) { Write-Host "Dynamic Rule : $DynamicRule" }
        Write-Host "----------------------------------`n"

    } catch {
        Write-Log "Failed to create group '$GroupName'. Error: $_" -Level ERROR
        throw
    }
}
#endregion

Write-Log "Script completed successfully."