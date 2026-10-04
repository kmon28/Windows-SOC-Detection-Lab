# Evidence Gallery

> **44 original lab artifacts** documenting architecture, telemetry collection, detection engineering, alert validation, threat hunting, incident investigation, dashboarding, IAM monitoring, and Windows hardening.

### 📂 [Browse all 44 screenshots →](screenshots/)

The gallery is organized so a reviewer can jump directly from a technical claim to the underlying evidence.

## Detection & Alert Validation

| Evidence | Analyst value |
|---|---|
| [Encoded PowerShell detection](screenshots/Splunk_Encoded_Powershell_Detection.png) | Sysmon process telemetry + SPL detection logic |
| [Encoded PowerShell alert triggered](screenshots/Splunk_Encoded_Powershell_Alert_Triggered.png) | Scheduled alert validation / Trigger History |
| [Repeated failed-logon detection](screenshots/SOC_Brute_Force_Failed_Logon_Detection.png) | Event 4625 aggregation and thresholding |
| [Failed-logon alert triggered](screenshots/SOC_Repeated_Failed_Logon_Alert_Triggered.png) | Authentication alert validation |
| [Privileged-group membership detection](screenshots/SOC_Privileged_Group_Membership_Detection.png) | Event 4728 AD/IAM monitoring |
| [Privileged-group alert triggered](screenshots/SOC_Privileged_Group_Alert_Triggered.png) | High-severity identity alert validation |

## Incident Investigation

| Evidence | Analyst value |
|---|---|
| [Encoded PowerShell — event context](screenshots/SOC_Incident_Encoded_PowerShell_Event_Context.png) | Time, host, user, and image attribution |
| [Encoded PowerShell — process lineage](screenshots/SOC_Incident_Encoded_PowerShell_Event_Process_Lineage.png) | Command line and parent-process evidence |
| [PowerShell parent-process analysis](screenshots/Splunk_Powershell_Parent_Process_Analysis.png) | Process relationship analysis |
| [Controlled PowerShell detection](screenshots/Splunk_Controlled_Powershell_Detection.png) | Detection-validation evidence |

**Full case narrative:** [IR-001 — Encoded PowerShell Investigation](../incident-reports/IR-001-encoded-powershell.md)

## Threat Hunting

| Evidence | Analyst value |
|---|---|
| [Process-chain threat hunt](screenshots/SOC_Process_Chain_Threat_Hunting.png) | Parent/child and command-line hunting |
| [Filtered CMD/PowerShell hunt](screenshots/SOC_Threat_Hunt_CMD_Powershell_Filtered.png) | Noise reduction and hunt refinement |
| [Controlled CMD detection](screenshots/SOC_Threat_Hunt_Controlled_CMD_Detection.png) | Known-activity validation |
| [Rare DNS query hunt](screenshots/SOC_DNS_Rare_Query_Threat_Hunt.png) | Frequency-based DNS hunting |
| [DNS-to-process correlation](screenshots/SOC_DNS_Query_Process_Correlation.png) | Query attribution to originating process |

## Telemetry Pipeline

| Evidence | Engineering value |
|---|---|
| [Sysmon ingestion in Splunk](screenshots/Splunk_Sysmon_Ingestion_Client01.png) | CLIENT01 telemetry searchable in SIEM |
| [Forwarder connection restored](screenshots/Client01_Splunk_Forwarder_Connection_Restored.png) | Endpoint → UF → Splunk pipeline troubleshooting |
| [Sysmon service running](screenshots/sysmon_service_status_running.png) | Endpoint telemetry service validation |
| [Sysmon Event ID 1 — Process Create](screenshots/Client01_Sysmon_EventID1_ProcessCreate_Details.png) | Process telemetry |
| [Sysmon Event ID 11 — File Create](screenshots/Client01_Sysmon_EventID11_FileCreate.png) | File telemetry |
| [Sysmon Event ID 22 — DNS Query](screenshots/Client01_Sysmon_EventsID22_DNSQuery.png) | DNS telemetry |
| [ipconfig process creation](screenshots/Sysmon_EventID1_ProcessCreate_ipconfig.png) | Controlled Event ID 1 validation |

## Active Directory, Audit Policy & Hardening

| Evidence | Engineering value |
|---|---|
| [AD DS / DNS role selection](screenshots/DC02_ADDS_DNS_ROLE_SELECTION.png) | Domain-controller build |
| [CLIENT01 joined to lab.local](screenshots/CLIENT01_DOMAIN_JOINED_lab.local.png) | Domain integration |
| [SOC audit GPO created](screenshots/01_GPO_SOC-AUDIT-POLICY_CREATED.png) | Centralized audit-policy engineering |
| [Audit Logon enabled](screenshots/02_AUDIT_LOGON_ENABLED.png) | Authentication telemetry configuration |
| [Kerberos auditing](screenshots/03_Kerberos_Authentication_Auditing.png) | Domain authentication visibility |
| [Process Creation auditing](screenshots/04_Audit_Process_Creation.png) | Windows process telemetry configuration |
| [Command-line logging enabled](screenshots/05_Command_Line_Logging_Enabled.png) | Command-line visibility |
| [DC02 Group Policy update](screenshots/06_dc02_Group_Policy_Update_Success.png) | Policy deployment validation |
| [CLIENT01 Group Policy update](screenshots/CLIENT01_GPO_UPDATE_SUCCESS.png) | Endpoint policy validation |
| [SMB/TCP 445 block validation](screenshots/Firewall_SMB445_Block_Validation.png) | Windows Firewall hardening |

## SOC Dashboard

| Dashboard panel |
|---|
| [Total Sysmon Events](screenshots/SOC_Dashboard_Total_Sysmon_Events.png) |
| [Process Creation](screenshots/SOC_Dashboard_Process_Creation.png) |
| [DNS Queries](screenshots/SOC_Dashboard_DNS_Queries.png) |
| [PowerShell Activity](screenshots/SOC_Dashboard_PowerShell_Activity.png) |
| [PowerShell + CMD Activity](screenshots/SOC_Dashboard_PowerShell_CMD_Activity.png) |
| [CMD Activity](screenshots/SOC_Dashboard_CMD_Activity.png) |
| [Process Activity Over Time](screenshots/SOC_Dashboard_Process_Activity_Over_Time.png) |
| [Recent Command-Line Activity](screenshots/SOC_Dashboard_Recent_Command_Line_Activity.png) |

## Complete Artifact Set

The sections above surface the strongest reviewer-facing evidence. **[Open the screenshots directory](screenshots/)** to inspect the complete 44-file set, including additional setup and validation artifacts.

## Evidence Standard

Screenshots support the analysis; they do not replace it. Controlled simulations are labeled as controlled, and suspicious-looking telemetry is not classified as malicious without supporting evidence. This keeps the portfolio technically defensible in an interview.
