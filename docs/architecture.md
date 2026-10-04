# Architecture & Telemetry Flow

## Objective
Build a compact Windows enterprise-style environment where identity, endpoint, and authentication telemetry can be collected, searched, alerted on, and investigated end to end.

## Components

| Component | Role | Security value |
|---|---|---|
| DC02 | Windows Server 2022, AD DS, DNS, GPO, Splunk Enterprise | Identity control plane + SIEM |
| CLIENT01 | Domain-joined Windows 10 endpoint | User endpoint and telemetry source |
| Sysmon | Endpoint instrumentation | Process creation, file creation, DNS |
| Windows Security Log | Native audit source | Authentication and AD group events |
| Splunk Universal Forwarder | Endpoint log transport | Sends telemetry to DC02 |
| Splunk Enterprise | Search, detection, alerting, dashboarding | SOC analysis layer |
| Windows Firewall | Host control | SMB/TCP 445 inbound hardening |

## Telemetry Pipeline

```text
CLIENT01
  ├─ Sysmon Operational Log ─┐
  └─ Windows Security Log ───┤
                             ▼
                  Splunk Universal Forwarder
                             │ TCP/9997
                             ▼
                         DC02 / Splunk
                             │
          ┌──────────────────┼──────────────────┐
          ▼                  ▼                  ▼
        Search            Alerts            Dashboard
          │                  │                  │
          └──────────────► Investigation ◄─────┘
```

DC02's own Windows Security log was also ingested locally to support Active Directory security-group monitoring.

## Key Audit Coverage
- Sysmon Event ID 1 — Process Create
- Sysmon Event ID 11 — File Create
- Sysmon Event ID 22 — DNS Query
- Windows Security Event ID 4625 — Failed Logon
- Windows Security Event ID 4728 — Member Added to Security-Enabled Global Group
- Advanced Audit Policy / Security Group Management
- Process command-line auditing

## Engineering Failure & Recovery
The Universal Forwarder transport path was reachable, but endpoint events initially failed to arrive. Forwarder logs showed Windows event-channel subscription failures with Access Denied. The service identity `NT SERVICE\SplunkForwarder` was added to **Event Log Readers**, the service was restarted, and fresh Sysmon activity became searchable.

This failure was useful because it separated three different layers that are often conflated during SIEM troubleshooting:

1. network reachability,
2. forwarder configuration,
3. operating-system permission to read the source telemetry.

## Security Boundaries & Limitations
This is a two-VM home-lab, not a production enterprise. It does not claim HA Splunk architecture, enterprise RBAC, EDR containment, or cloud-scale ingestion. The design goal was to demonstrate defensible analyst and security-engineering workflows with evidence that can be reproduced and explained.
