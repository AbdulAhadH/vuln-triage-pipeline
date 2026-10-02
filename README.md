# Vulnerability Management Pipeline

Python pipeline that takes raw Nessus Essentials scan output and turns it into a prioritized list of what to actually fix first, using CVSS, EPSS, and the CISA Known Exploited Vulnerabilities (KEV) catalog.  

A raw vulnerability scan gives severity scores (CVSS), but severity alone does not tell what is actually at risk right now. This project adds two more signals on top of CVSS: EPSS, which estimates how likely a CVE is to be exploited in the next 30 days, and the CISA KEV list, which confirms a CVE is already being exploited. Combining all three gives a more realistic ranking than CVSS alone.  

## Pipeline flow

```
┌───────────────────────┐
│   Nessus Essentials     │
│   credentialed scan      │
└───────────┬─────────────┘
            │ local REST API (export is a paid feature)
┌───────────▼─────────────┐
│   nessus_export.py        │
│   writes nessus_findings.csv │
└───────────┬─────────────┘
            │
┌───────────▼─────────────┐       ┌─────────────────────┐
│   enrich.py                │◄──────│ CISA KEV catalog (API)│
│   filters to real CVEs,    │◄──────│ EPSS scores (API)     │
│   applies priority formula │       └─────────────────────┘
└───────────┬─────────────┘
            │
┌───────────▼─────────────┐
│   remediation_queue.csv    │
│   ranked, highest first    │
└───────────────────────────┘
```

## What this lab covers

- [x] Deploy Nessus Essentials on Ubuntu and scan a Windows 11 VM lab target
- [x] Configure a credentialed scan (local admin account, Remote Registry, firewall rule) to get real vulnerability data 
- [x] Parse raw scan output and filter down to findings that map to a real CVE
- [x] Enrich each CVE with EPSS (likelihood of exploitation) and CISA KEV (confirmed active exploitation)
- [x] Build a priority formula that ranks confirmed active exploitation above raw CVSS score
- [x] Validate the ranked output against the real scan data

## Tech stack

| Component | Purpose |
|---|---|
| Nessus Essentials | Vulnerability scanner, free tier, limited to 16 IPs |
| Nessus REST API | Used to pull scan results locally since CSV/PDF export is Professional only |
| CISA KEV catalog | Confirms which CVEs are being actively exploited right now |
| EPSS (FIRST.org) | Estimates the probability a CVE will be exploited |
| Python (requests, csv) | Enrichment and ranking pipeline |

## Lab setup

- Host: Ubuntu 24.04, running Nessus Essentials
- Target: Windows 11 VM on a VirtualBox host only network 
- Scan type: Basic Network Scan, credentialed, using a local admin account

  ## Scan Results

![Nessus scan results](lab-vm-scan.jpg)

## Priority formula

If a CVE is on the CISA KEV list, it ranks above everything else, since that confirms it is being used in real attacks right now, regardless of its raw severity score:

```python
if in_kev:
    priority = 1000 + (cvss * 10)
else:
    priority = cvss * epss * 100
```

Everything not on the KEV list is ranked by severity times likelihood (CVSS x EPSS), so a severe but rarely targeted finding does not automatically outrank a moderate one that is commonly exploited.

## Result

Out of 129 total findings on the scan, 3 had an actual CVE number attached. The rest were informational checks (OS fingerprinting, open port lists, installed software detection, and similar). Here is how the pipeline ranked the 3 CVEs:

| Priority | CVE | Finding | CVSS | EPSS | In KEV |
|---|---|---|---|---|---|
| 1088.0 | CVE-2013-3900 | WinVerifyTrust Signature Validation | 8.8 | 0.446 | Yes |
| 67.5 | CVE-1999-0524 | ICMP Timestamp Request Date Disclosure | 2.1 | 0.322 | No |
| 3.3 | CVE-2022-0001 | Speculative Execution Config Check (Intel BHI) | 6.5 | 0.005 | No |

## Key finding

CVE-2022-0001 has a higher raw CVSS score than the ICMP finding above it, but it ranks last because almost nobody is actively trying to exploit it (EPSS of about 0.5%). CVE-2013-3900 ranks first because it is on CISA's KEV catalog, confirming it is used in real attacks today, even though it is not the highest CVSS score in the set. CVSS alone would have ranked these findings in a different order than what is actually urgent.


## Repo structure

```
vuln-triage-pipeline/
├── README.md
├── nessus_export.py        # pulls scan results via the local Nessus API
├── enrich.py                # enrichment and ranking pipeline
├── nessus_findings.csv      # raw scan output
└── remediation_queue.csv    # final ranked output
```

## What I would add next

- Scan more hosts to work with a larger dataset
- Add a couple of intentionally outdated programs to the lab VM to generate more CVEs to rank against each other
