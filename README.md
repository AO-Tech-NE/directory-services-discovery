# directory-services-discovery

## Overview

**directory-services-discovery** is a structured, PowerShell-based discovery framework for Active Directory, Domain Controllers, and Azure / Hybrid identity environments.

The repository is designed to support **deep, defensible discovery** prior to:

- Infrastructure changes
- Security hardening initiatives
- Directory modernization projects
- Azure / Entra hybrid transitions
- Incident response and forensic readiness
- MSP onboarding and environment assessments

The goal is to produce **repeatable, auditable discovery artifacts** that clearly differentiate:

- Environmental noise
- Legacy configuration debt
- True operational risk
- Pre-change impact factors

This repository intentionally avoids abstract “health scores” in favor of **raw, explainable findings**.

---

## Design Principles

- Read-only discovery by default
- No remediation actions inside discovery modules
- Clear separation of:
  - Data collection
  - Normalization
  - Reporting
- Noise-aware (Windows defaults vs actionable risk)
- Hybrid-first (on-prem AD + Entra ID / Azure AD)
- Deterministic output suitable for audit and change review

---

## Supported Environments

### Active Directory
- Single-forest / single-domain environments
- Multi-domain controller topologies
- Windows Server functional levels (2012 R2+)

### Domain Controllers
- Certificate trust stores
- Service configuration and dependencies
- Scheduled tasks
- Security-relevant configuration drift
- Baseline operational state

### Azure / Entra ID
- Tenant configuration
- Identity roles and privileges
- Conditional Access posture
- Authentication methods
- Device states and join types

### Hybrid Identity
- Azure AD Connect (PHS / PTA)
- Entra Cloud Sync
- Hybrid join scenarios
- Writeback features
- Identity boundary dependencies

---

## Repository Structure

```text
directory-services-discovery
│
├── README.md
├── CHANGELOG.md
├── STATUS.md
│
├── configs
│   ├── scope.json
│   ├── exclusions.json
│   └── thresholds.json
│
├── modules
│   ├── ActiveDirectory
│   │   ├── AD-Domain.psm1
│   │   ├── AD-DomainControllers.psm1
│   │   ├── AD-SitesAndReplication.psm1
│   │   ├── AD-OUsAndDelegation.psm1
│   │   ├── AD-GPOs.psm1
│   │   ├── AD-ServiceAccounts.psm1
│   │   ├── AD-Trusts.psm1
│   │   └── AD-DNS.psm1
│   │
│   ├── DomainController
│   │   ├── DC-Health.psm1
│   │   ├── DC-Certificates.psm1
│   │   ├── DC-Services.psm1
│   │   ├── DC-ScheduledTasks.psm1
│   │   ├── DC-SecurityBaseline.psm1
│   │   └── DC-Dependencies.psm1
│   │
│   ├── AzureAD
│   │   ├── AAD-Tenant.psm1
│   │   ├── AAD-UsersAndRoles.psm1
│   │   ├── AAD-ConditionalAccess.psm1
│   │   ├── AAD-AuthMethods.psm1
│   │   └── AAD-Devices.psm1
│   │
│   ├── Hybrid
│   │   ├── Hybrid-AADConnect.psm1
│   │   ├── Hybrid-CloudSync.psm1
│   │   ├── Hybrid-PasswordHash.psm1
│   │   └── Hybrid-Writeback.psm1
│   │
│   └── Common
│       ├── Logging.psm1
│       ├── Output.psm1
│       ├── Permissions.psm1
│       └── Utilities.psm1
│
├── scripts
│   ├── Invoke-ADDiscovery.ps1
│   ├── Invoke-DCDiscovery.ps1
│   ├── Invoke-AzureADDiscovery.ps1
│   ├── Invoke-HybridDiscovery.ps1
│   └── Invoke-FullDiscovery.ps1
│
├── reports
│   ├── raw
│   ├── normalized
│   └── summaries
│
├── examples
│   ├── Sample-DCReport.json
│   ├── Sample-ADSummary.md
│   └── Sample-HybridFindings.md
│
└── docs
    ├── Discovery-Methodology.md
    ├── PreChange-Impact-Model.md
    ├── Hybrid-Discovery-Notes.md
    └── Known-Windows-Noise.md
