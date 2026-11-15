# Detection Engineering

These detection artifacts accompany the original controlled lab evidence. **The original SPL was exercised during the Splunk trial, which has expired.** Subsequent source-code corrections are documented improvements; they are **not** claimed to have been re-executed in the expired SIEM.

| Use case | Primary telemetry | SPL | Sigma | Historical validation |
|---|---|---|---|---|
| Encoded PowerShell | Sysmon Event 1 | [Search](splunk/encoded-powershell.spl) | [Rule](sigma/encoded-powershell.yml) | Controlled process and triggered alert |
| Failed logons | Security Event 4625 | [Five-minute window search](splunk/failed-logons.spl) | [Event-level rule](sigma/failed-logon-event.yml) | Controlled failures and historical alert |
| Security group addition | Security Event 4728 | [Search](splunk/privileged-group-change.spl) | [Broad group-change rule](sigma/privileged-group-add.yml) | Controlled Domain Admins change and alert |
| Process-chain hunt | Sysmon Event 1 | [Search](splunk/process-chain-hunt.spl) | — | CMD/PowerShell baseline and test |
| Rare DNS hunt | Sysmon Event 22 | [Search](splunk/rare-dns-hunt.spl) | — | Query-to-process investigation |
| Process activity trend | Sysmon Event 1 | [Search](splunk/process-activity-timechart.spl) | — | Dashboard evidence |

## Analyst notes

- **SPL and Sigma are not interchangeable.** The failed-logon Sigma rule matches individual 4625 events; the SPL query counts events in **five-minute fixed buckets**, grouped by account, source IP, and host. It is not a sliding-window detector, and it may split activity crossing a bucket boundary.
- **Group scope:** The 4728 Sigma rule matches additions to any security-enabled global group, not only Domain Admins. A production high-severity rule needs sensitive group SID filtering and authorized-change context.
- **Encoded PowerShell:** Encoded syntax is an investigative signal, not a malware verdict. The Sigma rule is a portable reference and was not deployed to production.
- **XML parsing:** SPL extracts fields from the raw XML format observed in this lab. Confirm actual sourcetype and event formatting before reusing on a different SIEM.
- **Historical validation:** Screenshot evidence supports the original exercises; the revised searches and portable Sigma files are not asserted to be separately tested in the original environment.

## Detection lifecycle

```text
Telemetry → Baseline → Search → Tune → Controlled Validation
         → Alert Review → Investigation → Documented Disposition
```

[Evidence index](../evidence/README.md) · [Detection catalog](../docs/detection-catalog.md) · [IR-001](../incident-reports/IR-001-encoded-powershell.md)
