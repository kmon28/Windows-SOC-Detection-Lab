# Detection Catalog

| Detection / Hunt | Telemetry | Logic | Validation | ATT&CK |
|---|---|---|---|---|
| Encoded PowerShell | Sysmon EID 1 | PowerShell + `EncodedCommand` | Controlled execution; scheduled alert fired | T1059.001 |
| Repeated failed logons | Security EID 4625 | Count failures by target user; threshold ≥5 | Controlled failures for `socuser`; alert fired | T1110 |
| Privileged group membership | Security EID 4728 | Extract actor, member, group | Controlled Domain Admins add/remove; alert fired | T1098 |
| CMD/PowerShell hunt | Sysmon EID 1 | Filter command interpreters and collection noise | Controlled `whoami && ipconfig` | T1059.003 / T1033 / T1016 |
| Process-lineage hunt | Sysmon EID 1 | Image + command line + parent image | Baseline vs controlled activity | T1059 family visibility |
| Rare DNS hunt | Sysmon EID 22 | Low-frequency QueryName/Image pairs | One-off query + process context | Hunting telemetry; no malicious claim |

## Engineering Principles
- Validate collection before tuning detections.
- Extract fields from raw XML when normalized fields are unavailable.
- Reduce known tool noise without deleting source telemetry.
- Use thresholds where a single event is weak evidence.
- Validate alerts with controlled activity.
- Separate detection matches from incident verdicts.
- Document false-positive considerations and telemetry limitations.
