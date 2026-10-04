# Detection Engineering

The detections in this directory are the portable artifacts behind the screenshots and dashboard.

| Use case | Primary telemetry | SPL | Sigma | Validation |
|---|---|---|---|---|
| Encoded PowerShell | Sysmon EID 1 | [SPL](splunk/encoded-powershell.spl) | [Sigma](sigma/encoded-powershell.yml) | Controlled execution + triggered alert |
| Repeated failed logons | Security EID 4625 | [SPL](splunk/failed-logons.spl) | [Sigma](sigma/failed-logon-event.yml) | Controlled failures + triggered alert |
| Privileged group change | Security EID 4728 | [SPL](splunk/privileged-group-change.spl) | [Sigma](sigma/privileged-group-add.yml) | Controlled Domain Admins add/remove + triggered alert |
| Process-chain hunt | Sysmon EID 1 | [SPL](splunk/process-chain-hunt.spl) | — | Controlled CMD/PowerShell activity |
| Rare DNS hunt | Sysmon EID 22 | [SPL](splunk/rare-dns-hunt.spl) | — | Process/query correlation and baseline review |
| Process activity trend | Sysmon EID 1 | [SPL](splunk/process-activity-timechart.spl) | — | Dashboard time-series panel |

## Detection lifecycle used
```text
Telemetry → Baseline → Search → Tune → Controlled Validation
         → Scheduled Alert → Trigger Review → Investigation → Documentation
```

Sigma files are portfolio translations of the behaviors investigated in the lab; they are not claimed to have been deployed as production rules.
