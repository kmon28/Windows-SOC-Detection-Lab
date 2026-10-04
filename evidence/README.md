# Evidence Index

The lab produced **44 labeled screenshots** covering build, telemetry, detection, alert validation, threat hunting, dashboarding, IAM monitoring, and incident investigation.

## High-Value Evidence

| Evidence | What it demonstrates |
|---|---|
| `Splunk_Sysmon_Ingestion_Client01.png` | Endpoint → UF → Splunk ingestion |
| `Splunk_Encoded_Powershell_Detection.png` | Encoded PowerShell detection |
| `Splunk_Encoded_Powershell_Alert_Triggered.png` | Scheduled alert validation |
| `SOC_Brute_Force_Failed_Logon_Detection.png` | Thresholded Event 4625 analysis |
| `SOC_Repeated_Failed_Logon_Alert_Triggered.png` | Authentication alert trigger |
| `SOC_Privileged_Group_Membership_Detection.png` | Event 4728 AD/IAM monitoring |
| `SOC_Privileged_Group_Alert_Triggered.png` | High-severity privileged-group alert |
| `SOC_Process_Chain_Threat_Hunting.png` | Process lineage / command-line hunting |
| `SOC_DNS_Rare_Query_Threat_Hunt.png` | Low-frequency DNS hunting |
| `SOC_DNS_Query_Process_Correlation.png` | DNS → process correlation |
| `SOC_Incident_Encoded_PowerShell_Event_Context.png` | Incident event context |
| `SOC_Incident_Encoded_PowerShell_Event_Process_Lineage.png` | Incident process lineage |
| `Firewall_SMB445_Block_Validation.png` | Windows Firewall hardening evidence |
| `SOC_Dashboard_Process_Activity_Over_Time.png` | Time-based SOC dashboard analysis |

## Evidence Philosophy

The screenshots are supporting evidence, not the portfolio itself. The main README, detection catalog, SPL, Sigma, ATT&CK mapping, and incident report explain **what was done, why it matters, how it was validated, and what conclusions are justified**.

Controlled simulations are labeled as controlled. Rare or suspicious-looking telemetry is not called malicious without supporting evidence.

## Local Evidence Package

The complete screenshot set is preserved in the project evidence package. GitHub-facing documentation intentionally prioritizes the strongest artifacts so reviewers can navigate quickly.
