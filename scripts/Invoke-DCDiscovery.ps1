<#
.SYNOPSIS
Domain Controller discovery entrypoint for directory-services-discovery.

.DESCRIPTION
This script performs READ-ONLY discovery against a target Domain Controller.
It is the first implemented and validated discovery entrypoint in this repository.

All other Invoke-*Discovery.ps1 scripts are currently STUBS unless explicitly
marked otherwise in STATUS.md.

DESIGN GUARANTEES
- No remediation actions
- No configuration changes
- No writes outside the reports/ directory
- Safe to re-run
- Output is deterministic and explainable

STATUS
Implemented (baseline)
Validation in progress on real Domain Controllers.

AUTHOR
Cheri Leichleiter

.REPO
directory-services-discovery
#>
