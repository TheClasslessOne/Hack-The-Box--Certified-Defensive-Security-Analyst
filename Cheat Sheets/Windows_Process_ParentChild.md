
# Common Windows Normal Processes Parent/Child Relationships

This document organizes typical Windows processes and their expected parent/child relationships for reference in threat hunting and anomaly detection.

---

## winlogon.exe
- **Parent**: N/A
- **Children**:
  - **userinit.exe**
    - **Children**:
      - `cmd.exe` (or alike) with cmdline containing *\\*\\*\\*\\*\\*\\*\\*\\*\\*`Winlogon`\\*\\*\\*\\*\\* (stuff set to autostart via Netlogon Share)
      - `explorer.exe`

---

## explorer.exe
- **Children**:
  - Any process started interactively by a user session (e.g., Chrome, Edge)
  - Programs set to autostart (Runkey, StartupFolder)

---

## svchost.exe
- **Parents**:
  - `services.exe`
- **Children**:
  - `rundll32.exe`
  - Many DLL-hosted services; difficult to baseline
  - `dllhost.exe`
  - `wmiprvse.exe`, `wsmprovhost.exe`, `winrshost.exe`

---

## taskhost.exe / taskhostw.exe
- **Parents**: `svchost.exe` (Schedule)
- **Children**:
  - `C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngenTask.exe`
  - Top Seen: `DismHost.exe`, `WinSat.exe`, `WefAudit.exe`

---

## services.exe
- **Parent**: `wininit.exe`
- **Children**:
  - `svchost.exe` (many instances)
  - `spoolsv.exe`
  - `lsass.exe`
  - `dllhost.exe`
  - Third-party service processes

---

## spoolsv.exe
- **Parent**: `services.exe`
- **Children**:
  - `splwow64.exe` (for print driver redirection)
  - Occasionally `rundll32.exe`, `wscript.exe` (if autostarted scripts)

---

## lsass.exe
- **Parent**: `wininit.exe`
- **Children**:
  - Rare (generally no children; investigate if any are observed)

---

## wininit.exe
- **Parent**: `smss.exe`
- **Children**:
  - `services.exe`
  - `lsass.exe`
  - `lsm.exe` (legacy)
  - `winlogon.exe`

---

## wmiprvse.exe, wsmprovhost.exe, winrshost.exe
- **Parents**: `svchost.exe`
- **Children**:
  - Any WMI-related tasks (legit SCCM processes should be whitelisted)

---

## dllhost.exe
- **Parent**: `svchost.exe`
- **Children**:
  - COM Surrogate processes

---

## conhost.exe
- **Parent**: Many processes with console (e.g., `cmd.exe`, `powershell.exe`)
- **Children**:
  - None directly

---

## searchindexer.exe
- **Children**:
  - `searchfilterhost.exe`
  - `searchprotocolhost.exe`

---

## searchprotocolhost.exe
- **Parent**: `searchindexer.exe`

---

## searchfilterhost.exe
- **Parent**: `searchindexer.exe`

---

## wmiprvse.exe
- **Parent**: `svchost.exe`

---

## cscript.exe / wscript.exe
- **Parents**:
  - `services.exe`
  - `spoolsv.exe`
  - `explorer.exe`
- **Children**:
  - Arbitrary scripts; should be baselined

---

## rundll32.exe
- **Parents**:
  - `svchost.exe`
  - `spoolsv.exe`
  - `explorer.exe`
- **Children**:
  - DLL executions (e.g., control panel applets, printer drivers, etc.)

---

## notables
- **gsript.exe**: GPO related child process from `winlogon.exe`
- **smss.exe**: Root session manager, parent of `wininit.exe` and `csrss.exe`

---

## Red Flags (Suspicious Relationships)
- `userinit.exe` spawning `cmd.exe` or `powershell.exe`
- `services.exe` spawning non-standard children (except known service binaries)
- `lsass.exe` spawning any process (e.g., password dumper tools)
- `spoolsv.exe` spawning scripting engines (`cscript.exe`, `wscript.exe`)
- `wmiprvse.exe` unexpected child processes
- `taskhost.exe` spawning uncommon binaries

---

# Usage
This reference is intended to help distinguish normal vs abnormal parent-child process relationships in Windows. Deviations from these baselines should be investigated.
