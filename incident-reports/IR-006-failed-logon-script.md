# IR-006 — Reusable Failed-Logon Detection

**Status:** Controlled validation completed · **Platform:** Windows Server 2022 / PowerShell · **Evidence:** Screenshot 48

## Analyst summary
Created and executed a reusable PowerShell script, `Detect-FailedLogins.ps1`, to evaluate Windows Security failed-logon activity. The script finished without execution errors and returned **`OK: No threshold reached`** during the recorded test. This confirms a successful **no-alert execution path**, not that the detection was proven to trigger at its configured threshold.

## Detection hypothesis
A concentration of Windows Security **Event ID 4625** records for an account within a defined time window may indicate password guessing or an authentication misconfiguration. A single failed logon is not sufficient for an incident verdict.

## Method
1. Query Security events with a time-bounded `Get-WinEvent` filter.
2. Extract the target username and relevant source/network fields.
3. Count failures by identity within a stated lookback period.
4. Compare counts against an explicit threshold; output either the matching account(s) or a clear no-threshold status.
5. Record the execution and investigate source IP, status/substatus, logon type, and adjacent successful events before escalation.

## Validation outcome
- **Observed:** PowerShell script returned `OK: No threshold reached` and the prompt returned.
- **Not yet established from the recorded output:** a positive threshold trigger, false-positive rate, performance on a large Security log, or exact script parameter values.
- **Recommended follow-up:** commit the actual `Detect-FailedLogins.ps1` source after reviewing it for secrets, then add a controlled positive test and a documented negative test. Do not represent the current screenshot as proof of positive detection.

## Evidence
**Screenshot 48:** `48-IR006-Reusable-Detection-Script.png` (verify actual uploaded filename in [evidence/screenshots](../evidence/screenshots/)).

## Interview refresher
**What did you build?** A reusable PowerShell failed-authentication check using native Windows event logs, independent of a SIEM subscription.

**What was the result?** The script completed and reported that no account met the configured threshold in that run.

**Why does it matter?** A detection should be repeatable, observable, and explicit about its alert and no-alert outcomes. Positive validation remains a separate engineering step.


## Verified visual evidence

These screenshots are stored in the Kali assessment repository's shared chronological evidence folder; they document Windows SOC work rather than Kali execution.

**Evidence 48:** [Open full-resolution screenshot](https://github.com/kmon28/Kali-Linux-Security-Assessment-Lab/blob/main/screenshots/48-IR006-Reusable-Detection-Script.png)

![Evidence 48 — 48-IR006-Reusable-Detection-Script.png](https://raw.githubusercontent.com/kmon28/Kali-Linux-Security-Assessment-Lab/main/screenshots/48-IR006-Reusable-Detection-Script.png)
