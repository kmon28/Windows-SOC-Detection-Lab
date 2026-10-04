# Technical Reviewer Guide

This repository is designed to be reviewable in **5 minutes** or explorable in depth.

## 60-second review
1. Read the [main README](../README.md) architecture and detection highlights.
2. Open [IR-001](../incident-reports/IR-001-encoded-powershell.md) for the analyst workflow.
3. Review the [Detection Catalog](detection-catalog.md) for coverage and validation.
4. Review [MITRE ATT&CK Mapping](mitre-attack.md) for behavior-to-technique reasoning.

## What to challenge me on in an interview
- Why Event ID 4625 is useful but insufficient by itself to prove brute force.
- Why a rare DNS query should be triaged rather than labeled malicious.
- How parent process, user, command line, and time scope change a PowerShell verdict.
- Why filtering Splunk helper processes is tuning—not evidence deletion.
- How I diagnosed a forwarder pipeline where TCP connectivity worked but Windows event-channel permissions failed.
- Why Event ID 4728 is valuable for privileged-access monitoring.
- How I would port these concepts to Sentinel/Defender/Entra ID.

## Engineering artifacts
- **SPL:** executable search logic under `detections/splunk/`
- **Sigma:** portable detection logic under `detections/sigma/`
- **Incident report:** evidence → scope → finding → verdict → production response
- **Evidence index:** original screenshots supporting the documented work

## Design principle
The portfolio intentionally avoids claiming that every alert is an incident. The strongest signal of analyst maturity is not generating more alerts; it is reaching a justified conclusion from the available telemetry and documenting what is still unknown.
