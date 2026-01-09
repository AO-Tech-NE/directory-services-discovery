# Implementation Status

This repo is under active development. Do not assume modules are production-ready unless explicitly marked **Implemented** and validated on a real Domain Controller.

## Entry Scripts

- scripts/Invoke-DCDiscovery.ps1 — Implemented (local validated, DC validation pending)
- scripts/Invoke-ADDiscovery.ps1 — Stub
- scripts/Invoke-AzureADDiscovery.ps1 — Stub
- scripts/Invoke-HybridDiscovery.ps1 — Stub
- scripts/Invoke-FullDiscovery.ps1 — Stub

## Modules

### DomainController
- modules/DomainController/DC-Services.psm1 — Implemented (baseline, local validated)
- modules/DomainController/DC-Certificates.psm1 — Implemented (local validated, DC validation pending)
- modules/DomainController/DC-ScheduledTasks.psm1 — Implemented (local validated, DC validation pending)
- modules/DomainController/DC-SecurityBaseline.psm1 — Stub
- modules/DomainController/DC-Dependencies.psm1 — Stub
- modules/DomainController/DC-Health.psm1 — Stub

### ActiveDirectory
All modules — Stub

### AzureAD
All modules — Stub

### Hybrid
All modules — Stub

### Common
All modules — Stub

## Validation Rules

A component can be marked **Implemented** only when:
1. It runs end-to-end without errors on a real DC.
2. It writes artifacts under reports/raw.
3. Output JSON can be parsed cleanly.
4. Re-running does not mutate system state.
