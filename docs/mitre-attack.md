# MITRE ATT&CK Coverage

This matrix describes **behavioral detection coverage demonstrated in the lab**. It does not claim that a real adversary executed these techniques.

| Tactic | Technique | ID | Evidence / analytic |
|---|---|---|---|
| Execution | Command and Scripting Interpreter: PowerShell | **T1059.001** | Encoded PowerShell process creation, alert validation, IR-001 |
| Execution | Command and Scripting Interpreter: Windows Command Shell | **T1059.003** | Controlled `cmd.exe` execution and process-chain hunt |
| Discovery | System Owner/User Discovery | **T1033** | `whoami` captured through Sysmon → UF → Splunk |
| Discovery | System Network Configuration Discovery | **T1016** | Controlled `ipconfig` command-line telemetry |
| Credential Access | Brute Force: Password Guessing | **T1110.001** | Repeated failures against one account; Security EID 4625 threshold detection |
| Persistence / Privilege Escalation | Account Manipulation: Additional Local or Domain Groups | **T1098.007** | Controlled addition to Domain Admins; Security EID 4728 detection and alert |

## Mapping discipline

ATT&CK is used as a behavioral taxonomy—not decoration. A technique is included only where the collected telemetry and controlled behavior support the mapping.

### Authentication
The failed-logon rule detects a pattern **consistent with password guessing** when repeated failures target an account. Event ID 4625 by itself does not prove T1110.001; the behavioral sequence and context are what make the mapping useful.

### Privileged group membership
The controlled Domain Admins membership change maps more precisely to **T1098.007 — Additional Local or Domain Groups** than to generic T1098. Windows Security Event ID 4728 provides the underlying audit evidence.

### DNS
Sysmon Event ID 22 was used for DNS rarity hunting and process correlation. The low-frequency query was **not** mapped to Command and Control simply because it was rare. Rarity was treated as a pivot for investigation, and the available evidence did not support a malicious conclusion.

## Coverage philosophy

The goal is not to maximize the number of ATT&CK IDs in a README. The goal is to show that I can connect:
```text
behavior → telemetry → detection logic → analyst context → ATT&CK technique → defensible verdict
```
