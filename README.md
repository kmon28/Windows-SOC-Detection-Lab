# Windows SOC Detection & Threat Hunting Lab

> **Hands-on blue-team portfolio:** Active Directory + Sysmon + Splunk Enterprise, with detection engineering, alert validation, threat hunting, IAM monitoring, incident investigation, and Windows hardening.

![Windows](https://img.shields.io/badge/Windows_Server_2022-0078D4?logo=windows&logoColor=white)
![Splunk](https://img.shields.io/badge/Splunk_Enterprise-000000?logo=splunk&logoColor=white)
![Sysmon](https://img.shields.io/badge/Sysmon-Telemetry-5E5E5E)
![Active Directory](https://img.shields.io/badge/Active_Directory-IAM-0078D4)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-EA1B2D)
![Status](https://img.shields.io/badge/Project-Complete-2EA44F)

## Executive Summary

I built a Windows enterprise-style security lab to practice the complete defensive workflow: **collect telemetry → engineer detections → validate alerts → hunt behavior → investigate context → document conclusions**.

The environment uses Windows Server 2022 (**DC02**) as an AD DS/DNS domain controller and a domain-joined Windows 10 endpoint (**CLIENT01**). Sysmon and Windows Security telemetry feed Splunk Enterprise through the Universal Forwarder. I built and validated detections for encoded PowerShell, repeated failed logons, privileged AD group changes, command execution, process lineage, and DNS behavior.

> **Scope:** controlled home-lab simulations are explicitly labeled and are not represented as production incident-response experience.

## Architecture

```text
                         lab.local
                            │
       ┌────────────────────┴────────────────────┐
       │ DC02 — Windows Server 2022             │
       │ AD DS • DNS • GPO • Security Logs      │
       │ Splunk Enterprise :8000 / :9997        │
       └────────────────────▲────────────────────┘
                            │ TCP 9997
                            │ Splunk UF
       ┌────────────────────┴────────────────────┐
       │ CLIENT01 — Windows 10                  │
       │ Domain Joined • Sysmon • Security Logs │
       │ Splunk Universal Forwarder             │
       └─────────────────────────────────────────┘
```

VirtualBox host-only network: `192.168.56.0/24` + NAT. DC02: `192.168.56.101`; CLIENT01: `192.168.56.102`.

## Recruiter / Interviewer Fast Path

| Capability | Evidence |
|---|---|
| **Technical reviewer guide** | [5-minute review path](docs/reviewer-guide.md) |
| Architecture | [Telemetry flow & engineering notes](docs/architecture.md) |
| Incident analysis | [IR-001 — Encoded PowerShell](incident-reports/IR-001-encoded-powershell.md) |
| Detection engineering | [Detection Catalog](docs/detection-catalog.md) |
| ATT&CK reasoning | [MITRE ATT&CK Mapping](docs/mitre-attack.md) |
| SPL | [Splunk detections](detections/splunk/) |
| Detection-as-code | [Sigma rules](detections/sigma/) |
| Evidence trail | [Screenshot index](evidence/README.md) |

## Detection Engineering Highlights

### Encoded PowerShell — T1059.001
Sysmon Event ID 1 was searched for PowerShell processes containing `EncodedCommand`. The detection became a scheduled Splunk alert, was validated with controlled activity, and was investigated using host, user, command-line, timestamp, and parent-process context.

**Verdict:** true-positive detection of intentionally generated lab behavior; no claim of compromise.

### Repeated Failed Logons — T1110
Windows Security Event ID 4625 was aggregated by target account and thresholded at five or more failed attempts. Controlled failures for `socuser` validated the search and scheduled alert.

```spl
index=main source="WinEventLog:Security" "<EventID>4625</EventID>"
| rex field=_raw "Name='TargetUserName'>(?<TargetUserName>[^<]+)"
| stats count as FailedAttempts by TargetUserName
| where FailedAttempts >= 5
| sort - FailedAttempts
```

### Privileged AD Group Change — T1098.007
Advanced Security Group Management auditing was enabled. A controlled addition of `employee.user` to **Domain Admins** generated Event ID 4728. Splunk extracted actor, member, and group context; a high-severity scheduled alert was validated; the test account was immediately removed.

### Process-Lineage Threat Hunting
Sysmon Event ID 1 telemetry was analyzed using image, command-line, and parent-image fields. Known Splunk Universal Forwarder helper activity was filtered to reduce collection noise while retaining raw telemetry.

### DNS Rarity & Process Correlation
Sysmon Event ID 22 was grouped by process/query. A low-frequency query to `aefd.nelreports.net` was correlated to `msedgewebview2.exe` and compared with that process's broader DNS behavior.

**Conclusion:** rarity is a hunting lead—not a malicious verdict. Available telemetry did not justify escalation.

## SOC Dashboard

Splunk Dashboard Studio surfaces total Sysmon telemetry, process creation, DNS queries, PowerShell/CMD activity, process activity over time, and recent command-line activity.

## Engineering & Troubleshooting

The build required AD DS/DNS, domain join, GPO validation, advanced audit policy, process command-line auditing, Sysmon Event IDs 1/11/22, Splunk receiver configuration, DC02 Security-log ingestion, Universal Forwarder troubleshooting, and Windows Firewall SMB/TCP 445 hardening.

A significant ingestion failure was traced to Windows event-channel permissions for `NT SERVICE\SplunkForwarder`. Adding the service identity to **Event Log Readers** restored the endpoint → forwarder → TCP 9997 → Splunk pipeline.

## What This Project Proves

This project is intentionally broader than a SIEM installation exercise. It demonstrates that I can:

- build and troubleshoot a Windows identity + endpoint telemetry pipeline;
- reason across **Active Directory, endpoint telemetry, authentication, DNS, and host firewall controls**;
- translate raw Windows XML into usable SPL fields;
- create behavioral detections and scheduled alerts;
- validate detection logic with controlled activity instead of assuming it works;
- reduce known collection noise while preserving raw evidence;
- pivot from an alert into a scoped investigation;
- distinguish a **true-positive detection** from a **malicious incident verdict**;
- map observed behavior to MITRE ATT&CK without over-mapping;
- express core analytics as portable Sigma detection-as-code;
- document limitations, tuning opportunities, and production improvements.

## Deep-Dive Documentation

| Document | Purpose |
|---|---|
| [Architecture & Telemetry](docs/architecture.md) | Components, data flow, audit sources, troubleshooting |
| [Detection Catalog](docs/detection-catalog.md) | Hypotheses, logic, validation, false positives, tuning |
| [IR-001 — Encoded PowerShell](incident-reports/IR-001-encoded-powershell.md) | Full SOC investigation and disposition |
| [MITRE ATT&CK Coverage](docs/mitre-attack.md) | Evidence-backed behavior mapping |
| [Technical Reviewer Guide](docs/reviewer-guide.md) | Interview discussion points and fast review path |
| [Evidence Index](evidence/README.md) | Screenshot inventory and evidence purpose |

## Engineering Principles

1. **Telemetry before detections.** A perfect query is useless when collection is broken.
2. **Tune noise; don't hide it.** Known collection activity was filtered analytically while raw data remained intact.
3. **Detection ≠ verdict.** Suspicious indicators were investigated in context before conclusions were assigned.
4. **Identity is security telemetry.** Privileged-group monitoring connects SIEM operations directly to IAM risk.
5. **Document limitations.** Missing evidence is recorded rather than inferred or fabricated.

## Repository Layout

```text
├── README.md
├── incident-reports/
├── detections/
│   ├── splunk/
│   └── sigma/
├── docs/
└── evidence/
    └── screenshots/
```

## Skills Demonstrated

`Splunk Enterprise` · `SPL` · `Sysmon` · `Windows Security Events` · `Active Directory` · `Group Policy` · `IAM Monitoring` · `Detection Engineering` · `Threat Hunting` · `Incident Analysis` · `Windows Firewall` · `MITRE ATT&CK` · `Sigma` · `DNS Analysis` · `VirtualBox`

## Portfolio Roadmap

**Completed:** Windows SOC / Detection Engineering  
**Next:** Network Traffic Analysis / Wireshark  
**Planned:** Azure · Entra ID · Sentinel · Defender · Cloud IAM · Conditional Access
