# MITRE ATT&CK Mapping

This mapping describes **behavioral relevance and detection coverage**, not claims that a real adversary executed these techniques.

| Technique | ID | Lab evidence |
|---|---|---|
| PowerShell | T1059.001 | Encoded PowerShell process creation, SPL detection, alert validation, investigation |
| Windows Command Shell | T1059.003 | Controlled `cmd.exe` activity and process-chain hunting |
| System Owner/User Discovery | T1033 | Controlled `whoami` captured in endpoint telemetry |
| System Network Configuration Discovery | T1016 | Controlled `ipconfig` captured in endpoint telemetry |
| Brute Force | T1110 | Repeated failed-logon behavioral detection using EID 4625 |
| Account Manipulation | T1098 | Privileged-group membership monitoring using EID 4728 |

## DNS Note
Sysmon Event ID 22 was used for DNS hunting and process correlation. Rare DNS activity was **not** labeled Command and Control solely because it was infrequent. ATT&CK mapping follows evidence, not keyword matching.
