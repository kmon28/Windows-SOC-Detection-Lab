# Windows SOC | Analyst triage quick reference

A practical entry point to the documented Windows investigations. These are controlled lab observations, not production incidents.

| Signal | Initial question | Corroboration | Common alternative |
|---|---|---|---|
| Sysmon Event ID 1: encoded PowerShell | What process launched PowerShell and with which arguments? | Parent image, command line, user, timestamp, related events | Legitimate administration or deployment tooling |
| Security Event ID 4625: repeated failures | Are failures clustered by account, source and time? | Logon type, source address, 4624 success events, account context | Mistyped password, stale service credentials |
| Security Event ID 4728: privileged group membership | Who added which member to which group? | Subject, target group, change ticket, later 4729 removal | Authorized administrative change |
| Security Event ID 4769: service-ticket activity | Is expected Kerberos telemetry being collected? | Audit policy, domain controller event channel, relevant service activity | Logging configuration gap, not absence of authentication |
| Sysmon Event ID 22: uncommon DNS query | Which process made the query and what else did it contact? | Process lineage, DNS frequency, destination context | Browser or embedded WebView traffic |

## Triage sequence
1. **Confirm the data source.** Verify host, log channel, event ID and timestamp before drawing conclusions.
2. **Establish a baseline.** Compare the activity with expected administrative and application behavior.
3. **Correlate.** Join events by account, host, source IP, process and a defensible time window.
4. **Assess competing explanations.** A matching detection rule is not itself proof of compromise.
5. **Document disposition.** State the observed behavior, supporting artifacts, uncertainty and next action.

## Case studies
- [Encoded PowerShell](../incident-reports/IR-001-encoded-powershell.md)
- [Failed-logon detection](../incident-reports/IR-006-failed-logon-script.md)
- [SMB/Kerberos audit recovery](../incident-reports/IR-007-smb-kerberos-audit-recovery.md)
- [Detection catalog](detection-catalog.md)

## Evidence boundary
The original exercises were validated during the lab. Historical Splunk evidence remains historical; the trial is no longer active. Reconstructed code should be evaluated as its own implementation rather than assumed identical to the VM original.
