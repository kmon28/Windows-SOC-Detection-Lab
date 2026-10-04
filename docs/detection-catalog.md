# Detection & Threat-Hunting Catalog

This catalog documents the analytical intent behind each use case, not just the SPL syntax.

| Use case | Telemetry | Detection / hunt logic | Validation | ATT&CK | Primary risk |
|---|---|---|---|---|---|
| Encoded PowerShell | Sysmon EID 1 | PowerShell + encoded-command syntax | Controlled execution; scheduled alert fired | T1059.001 | Obfuscated/suspicious script execution |
| Repeated failed logons | Security EID 4625 | Aggregate failures by target user; threshold ≥5 | Five controlled failures; alert fired | T1110.001 | Password guessing / credential attack |
| Privileged group membership | Security EID 4728 | Extract actor, member, target group | Controlled Domain Admins add/remove; alert fired | T1098.007 | Privilege escalation / persistence |
| CMD/PowerShell hunt | Sysmon EID 1 | Command interpreter + command-line extraction | Controlled `whoami && ipconfig` | T1059.003 / T1033 / T1016 | Execution + discovery |
| Process-lineage hunt | Sysmon EID 1 | Image + command line + parent image | Baseline vs controlled activity | T1059 family visibility | Suspicious execution chains |
| Rare DNS hunt | Sysmon EID 22 | Low-frequency QueryName/Image pairs | Query → process correlation + baseline | Investigative only | Beaconing / unusual destinations as hypotheses |
| File creation visibility | Sysmon EID 11 | File-create telemetry collection | Collection validation | — | Payload/artifact visibility |
| Process activity trend | Sysmon EID 1 | Time-series process counts | Dashboard validation | — | Behavioral baselining |

## Detection lifecycle

```text
Define hypothesis
      ↓
Validate telemetry
      ↓
Write SPL / extract fields
      ↓
Baseline normal behavior
      ↓
Tune obvious collection noise
      ↓
Generate controlled test
      ↓
Confirm search result
      ↓
Schedule alert where appropriate
      ↓
Confirm trigger history
      ↓
Investigate context
      ↓
Document verdict + limitations
```

## Engineering decisions

### Encoded PowerShell
**Signal:** PowerShell process creation containing encoded-command syntax.  
**Why it matters:** encoding can reduce readability and appears in both administration and malicious execution.  
**False-positive considerations:** legitimate scripts, software deployment, administrative automation.  
**Tuning direction:** add normalized command-line fields, Script Block Logging, parent-process context, network correlation, and approved-automation baselines.

### Repeated failed logons
**Signal:** five or more Event ID 4625 failures for a target account.  
**Why it matters:** repeated authentication failure can indicate password guessing.  
**False-positive considerations:** forgotten passwords, stale credentials, services, mapped drives, user error.  
**Tuning direction:** source host/IP, logon type, failure reason/status, success-after-failure correlation, time-of-day baseline, privileged-account weighting.

### Privileged group membership
**Signal:** Event ID 4728 showing a member added to a security-enabled global group.  
**Why it matters:** unexpected privileged-group additions can create persistent elevated access.  
**False-positive considerations:** approved provisioning, change windows, break-glass procedures.  
**Tuning direction:** restrict high-priority logic to sensitive groups such as Domain Admins; enrich with actor, member, ticket/change context, and follow-on authentication.

### Rare DNS
**Signal:** low-frequency query/process combinations.  
**Why it matters:** low prevalence can surface unusual software behavior or potential beaconing.  
**False-positive considerations:** software updates, telemetry endpoints, browser/WebView components, first-seen legitimate services.  
**Tuning direction:** prevalence over longer windows, process reputation, destination age/category, network connection correlation, peer-host comparison.

## Quality controls
- Collection was tested before detection tuning.
- Raw XML was field-extracted where normalized fields were unavailable.
- Known collection noise was filtered from analytical views, not deleted from source data.
- Thresholds were used where single events are weak evidence.
- Scheduled detections were validated with controlled activity and Trigger History.
- Detection matches and incident verdicts are documented separately.
- Telemetry gaps are stated rather than filled with assumptions.
