**Vulnerability Management Pipeline**  
Python pipeline that takes raw Nessus Essentials scan output and turns it into a prioritized list of what to actually fix first, using CVSS, EPSS, and the CISA Known Exploited Vulnerabilities (KEV) catalog.  
**Why**  
A raw vulnerability scan gives severity scores (CVSS), but severity alone does not tell what is actually at risk right now. A critical bug nobody is exploiting matters less in practice than a moderate bug that is actively being used in real attacks. This project adds two more signals on top of CVSS: EPSS, which estimates how likely a CVE is to be exploited in the next 30 days, and the CISA KEV list, which confirms a CVE is already being exploited. Combining all three gives a more realistic ranking than CVSS alone.  
**Lab setup**  
- Host: Ubuntu 24.04, running Nessus Essentials  
- Target: Windows 11 VM on a VirtualBox host only network (192.168.56.0/24)  
- Scan type: Basic Network Scan, credentialed, using a local admin account  
Nessus Essentials does not include scan export (CSV/PDF export is a Professional only feature), so the scan results were pulled directly from Nessus's own local API instead.  
**Pipeline**  
1. nessus_export.py logs into the local Nessus API and pulls every finding from the scan into nessus_findings.csv  
2. enrich.py reads that CSV, keeps only findings that have a real CVE attached, looks up each one's EPSS score and CISA KEV status, calculates a priority score, and writes remediation_queue.csv, sorted highest priority first  
**Priority formula**  
If a CVE is on the CISA KEV list, it ranks above everything else, since that confirms it is being used in real attacks right now, regardless of its raw severity score:  
if in_kev:  
     priority = 1000 + (cvss * 10)  
 else:  
     priority = cvss * epss * 100  
   
Everything not on the KEV list is ranked by severity times likelihood (CVSS x EPSS), so a severe but rarely targeted finding does not automatically outrank a moderate one that is commonly exploited.  
**Result**  
Out of 129 total findings on the scan, 3 had an actual CVE number attached. The rest were informational checks (OS fingerprinting, open port lists, installed software detection, and similar). Here is how the pipeline ranked the 3 CVEs:  
| | | | | | |  
|-|-|-|-|-|-|  
| **Priority** | **CVE** | **Finding** | **CVSS** | **EPSS** | **In KEV** |   
| 1088.0 | CVE-2013-3900 | WinVerifyTrust Signature Validation | 8.8 | 0.446 | Yes |   
| 67.5 | CVE-1999-0524 | ICMP Timestamp Request Date Disclosure | 2.1 | 0.322 | No |   
| 3.3 | CVE-2022-0001 | Speculative Execution Config Check (Intel BHI) | 6.5 | 0.005 | No |   
   
CVE-2022-0001 actually has a higher raw CVSS score than the ICMP finding above it, but it ranks last because almost nobody is actively trying to exploit it (EPSS of about 0.5%). CVE-2013-3900 ranks first because it is on CISA's KEV catalog, confirming it is used in real attacks, even though it is not the highest CVSS score in the set. CVSS alone would have ranked these differently than what is actually urgent.  
   
**What I would add next**  
- Scan more hosts to work with a larger dataset  
- Add a couple of intentionally outdated programs to the lab VM to generate more CVEs to rank against each other  
   
**Files**  
- nessus_export.py: pulls scan results out of Nessus Essentials through its local API, since the export button is a paid feature  
- enrich.py: the enrichment and ranking pipeline  
- nessus_findings.csv: raw scan output  
- remediation_queue.csv: final ranked output  
