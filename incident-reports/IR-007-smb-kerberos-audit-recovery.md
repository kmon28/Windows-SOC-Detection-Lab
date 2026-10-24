# IR-007 — SMB Network Authentication and Kerberos Audit Recovery

**Case type:** Controlled Windows identity investigation · **Date:** 2026-10-24 · **Environment:** Isolated VirtualBox `lab.local` · **Disposition:** Expected lab activity; audit-visibility gap corrected

## Executive finding
A deliberately initiated SMB session from CLIENT01 (`192.168.56.102`) to the domain controller (`192.168.56.101`) using `LAB\socuser` was correlated with Windows Security **4624, Logon Type 3** on DC02. During follow-up Kerberos analysis, recent **4769** service-ticket records were missing. Effective audit policy showed **No Auditing** after Group Policy refresh. Configuring **Audit Kerberos Service Ticket Operations — Success and Failure** in the domain-controller GPO and refreshing policy restored event collection. Three new **4769** records appeared on October 24 (two at 01:55:57 and one at 01:56:54, per lab observations).

**Security conclusion:** The session demonstrates authenticated network access and visibility restoration. It does **not** establish credential compromise, malicious lateral movement, or an attacker-controlled system.

## Investigation question
Can a defender attribute a remote SMB authentication to an account and originating host, then validate that the domain controller logs subsequent Kerberos service-ticket activity?

## Environment and telemetry
| Component | Role |
|---|---|
| DC02 / Windows Server 2022 | Domain controller, target SMB service, Windows Security events |
| CLIENT01 / Windows 10 | Source workstation, `192.168.56.102` |
| Domain | `lab.local` |
| Identity | `LAB\socuser` (SMB test); `LAB\Administrator` (separate Kerberos troubleshooting session) |
| Network | Host-only `192.168.56.0/24` |
| Event 4624 | Successful logon; **Type 3** identifies network logon |
| Event 4769 | Kerberos service-ticket request on a domain controller |

## Procedure and evidence interpretation
1. **Generate test traffic.** From CLIENT01, the operator ran `net use \\192.168.56.101\IPC$ /user:LAB\socuser *` and reported successful completion. This is an authenticated IPC$ connection; it is not proof of remote code execution.
2. **Correlate host and account.** On DC02, the analyst queried Security 4624, filtered the **New Logon** account `socuser`, and extracted logon type and source network address. The matching record showed **Type 3** and source `192.168.56.102`. Avoid confusing the **Subject** identity with the **New Logon** identity or treating a computer account ending in `$` as `socuser`.
3. **Investigate service tickets.** The initial search for 4769 found only older October 17 entries. That absence alone was not evidence that Kerberos failed.
4. **Diagnose auditing.** `auditpol /get /subcategory:"Kerberos Service Ticket Operations"` showed **No Auditing**. A temporary `auditpol /set` change reverted after `gpupdate /force`, suggesting effective Group Policy was taking precedence.
5. **Remediate at the policy source.** In Group Policy Management, configure **Default Domain Controllers Policy → Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies → Account Logon → Audit Kerberos Service Ticket Operations** for **Success and Failure**. Refresh policy and confirm the effective setting.
6. **Retest.** A ticket request for the actual DC host service principal succeeded. Fresh 4769 entries dated October 24 appeared after policy correction. **Important attribution limit:** The later 4769 tests were initiated under `LAB\Administrator` on DC02; they should not be represented as proof that `socuser` on CLIENT01 generated those particular ticket records.

## Reusable queries
```powershell
# On DC02 (elevated); account and source are in the event properties.
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 5000 |
  Where-Object { $_.Properties[5].Value -eq 'socuser' } |
  Select-Object -First 10 TimeCreated, Id,
    @{N='LogonType';E={$_.Properties[8].Value}},
    @{N='SourceIP';E={$_.Properties[18].Value}}

# Validate the effective domain-controller audit policy
auditpol /get /subcategory:"Kerberos Service Ticket Operations"

# Examine recently logged service-ticket requests
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} -MaxEvents 10 |
  Select-Object TimeCreated, Id
```
**Production note:** Property indexes are event-schema dependent. For durable detection content, parse XML by named `Data Name` fields, bound queries by time, and correlate user, source, destination, ticket service, and outcome. Audit policy changes should follow change control and be reviewed for log-volume impact.

## Detection and engineering assessment
- **Validated:** successful network logon attribution (4624); policy persistence after refresh; new Kerberos service-ticket event generation (4769).
- **Not validated:** attacker intent, lateral code execution, credential theft, or direct correlation between the later Administrator ticket requests and the earlier `socuser` SMB logon.
- **Potential false positives:** routine file sharing, administrative tools, GPO processing, machine-account activity, and legitimate Kerberos renewals.
- **Next engineering improvements:** export event XML and event record IDs; correlate 4769 ticket service/client IP with 4624 source; add 5140/5145 share access where auditing permits; validate repeated logon and unusual source baselines; use a dedicated audit GPO with documented precedence.

## Evidence map
| Screenshot | Demonstrates |
|---|---|
| **49 — IR-007 SMB Network Logon** | `socuser` 4624 / Type 3 / CLIENT01 source IP |
| **50 — IR-007 Kerberos 4769 Audit Validation** | Newly collected 4769 events following audit-policy correction |

**Evidence location:** [Screenshots directory](../evidence/screenshots/). Exact uploaded filenames should be checked against the repository before adding direct image links.

## Interview refresher
**What did you detect?** A domain-account network logon from a known workstation to the DC, followed by a separate test confirming Kerberos service-ticket auditing.

**What broke?** A local audit setting was overwritten by effective Group Policy; the domain-controller policy needed to be fixed.

**What did you prove?** The end-to-end method: generate known activity → inspect identity/source fields → identify telemetry gaps → correct policy → retest with fresh timestamps.

**Why wasn't this an incident?** All observed access was intentionally generated in an isolated lab. Authentication evidence alone does not establish malicious lateral movement.
