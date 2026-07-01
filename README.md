# entra-iam-scripts

PowerShell automation scripts for Microsoft Entra ID identity lifecycle management, built using the Microsoft Graph PowerShell SDK.

## About

This repository is a growing library of production-ready IAM automation scripts built for real-world Entra ID environments. Scripts follow least-privilege principles, include full audit logging, and support `-WhatIf` for safe pre-flight testing.

Built by [CJ. Williams](https://github.com/cjwilliamstech)

---

## Environment

| Component | Version |
|---|---|
| PowerShell | 7.6.3 |
| Microsoft Graph SDK | 2.38.0 |
| Platform | Ubuntu 22.04 LTS |
| Identity Platform | Microsoft Entra ID |

---

## Prerequisites

### 1. Install PowerShell 7

```bash
curl -sSL https://packages.microsoft.com/keys/microsoft.asc | sudo tee /etc/apt/trusted.gpg.d/microsoft.asc
curl -sSL https://packages.microsoft.com/config/ubuntu/22.04/prod.list | sudo tee /etc/apt/sources.list.d/microsoft-prod.list
sudo apt update && sudo apt install -y powershell
```

### 2. Install Microsoft Graph SDK

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

### 3. Connect to your Entra ID tenant

```powershell
Connect-MgGraph -Scopes "User.ReadWrite.All","Directory.ReadWrite.All","AuditLog.Read.All" -TenantId "your-tenant-id" -UseDeviceAuthentication
```

---

## Script Library

### New-EntraUser.ps1
Provisions a new user in Microsoft Entra ID via Microsoft Graph.

**Features:**
- Auto-derives UPN and display name from first/last name and tenant domain
- Generates a secure 16-character temporary password
- Prompts interactively if user already exists
- Full audit logging to `logs/`
- `-WhatIf` support for pre-flight testing

**Required Scopes:** `User.ReadWrite.All`, `Directory.ReadWrite.All`

**Usage:**
```powershell
# Dry run
.\scripts\New-EntraUser.ps1 -FirstName "Jane" -LastName "Smith" -Department "Finance" -JobTitle "Analyst" -WhatIf

# Live run
.\scripts\New-EntraUser.ps1 -FirstName "Jane" -LastName "Smith" -Department "Finance" -JobTitle "Analyst"
```

---

### Remove-EntraUser.ps1
Performs structured six-step offboarding of an Entra ID user.

**Offboarding Steps:**
1. Disable account — blocks sign-in immediately
2. Revoke all active sessions — invalidates live tokens
3. Remove group memberships — strips resource access
4. Remove directory role assignments — strips admin privileges
5. Hide from Global Address List — removes from email directory
6. Delete user — choice of soft delete (30-day recovery) or permanent delete

**Required Scopes:** `User.ReadWrite.All`, `Directory.ReadWrite.All`

**Usage:**
```powershell
# Dry run
.\scripts\Remove-EntraUser.ps1 -UserPrincipalName "jane.smith@contoso.onmicrosoft.com" -WhatIf

# Live run
.\scripts\Remove-EntraUser.ps1 -UserPrincipalName "jane.smith@contoso.onmicrosoft.com"
```

---

### Get-StaleAccounts.ps1
Identifies inactive Entra ID accounts based on last sign-in activity.

**Features:**
- Configurable inactivity threshold (default: 90 days)
- Filters for guest accounts and disabled accounts
- Exports findings to timestamped CSV in `logs/`
- Interactive per-account action prompt — disable, skip, or skip all
- `-WhatIf` support for pre-flight testing

**Required Scopes:** `User.Read.All`, `AuditLog.Read.All`, `Directory.Read.All`

**License Requirement:** Microsoft Entra ID P1 or P2 (for SignInActivity data)

**Usage:**
```powershell
# Default 90-day threshold, dry run
.\scripts\Get-StaleAccounts.ps1 -WhatIf

# 30-day threshold, exclude guests and disabled accounts
.\scripts\Get-StaleAccounts.ps1 -DaysInactive 30 -ExcludeGuests -ExcludeDisabled

# Live run with custom threshold
.\scripts\Get-StaleAccounts.ps1 -DaysInactive 60
```

---

## Planned Scripts

| Script | Description | Status |
|---|---|---|
| `Get-UserAccessReport.ps1` | Report on user role and group memberships | Planned |
| `Set-ConditionalAccessReport.ps1` | Audit and report Conditional Access policies | Planned |
| `AI Access Review Summarizer` | Python + Azure OpenAI access review summaries | Planned |
| `Stale Access Anomaly Detector` | PowerShell + Azure OpenAI anomaly detection | Planned |

---

## Repository Structure

```
entra-iam-scripts/
├── scripts/          # PowerShell automation scripts
├── logs/             # Audit logs and CSV reports (git ignored)
├── docs/             # Additional documentation
└── .gitignore        # Excludes logs and credentials
```