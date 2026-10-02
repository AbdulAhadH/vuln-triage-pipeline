#!/usr/bin/env python3
"""
enrich.py

Reads Nessus findings (nessus_findings.csv), keeps only the rows that have
a real CVE attached, looks up each CVE's EPSS score and CISA KEV status,
calculates a priority score, and writes a ranked remediation_queue.csv.

 load_findings():    read the CSV into a list of dictionaries
 get_cve_rows():     keep only rows that actually have a CVE
 get_kev_list():     download CISA's Known Exploited Vulnerabilities list
 get_epss_score():   look up one CVE's EPSS (likelihood of exploitation)
calculate_priority(): turn CVSS + EPSS + KEV-status into one ranking number
"""

import csv
import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


def load_findings(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def get_cve_rows(findings):
    result = []
    for row in findings:
        if row["cve"].strip():
            result.append(row)
    return result


def get_kev_list():
    response = requests.get(KEV_URL)
    data = response.json()
    return {entry["cveID"] for entry in data["vulnerabilities"]}


def get_epss_score(cve_id):
    response = requests.get(EPSS_URL, params={"cve": cve_id})
    data = response.json()
    if data["data"]:
        return float(data["data"][0]["epss"])
    return 0.0


def calculate_priority(cvss, epss, in_kev):
    if in_kev:
        return 1000 + (cvss * 10)
    return cvss * epss * 100


def main():
    findings = load_findings("nessus_findings.csv")
    cve_rows = get_cve_rows(findings)
    kev_set = get_kev_list()

    enriched = []
    for row in cve_rows:
        cve_id = row["cve"]
        cvss = float(row["cvss3_base_score"] or row["cvss_base_score"] or 0)
        epss = get_epss_score(cve_id)
        in_kev = cve_id in kev_set
        priority = calculate_priority(cvss, epss, in_kev)

        enriched.append({
            "cve": cve_id,
            "priority_score": priority,
            "cvss": cvss,
            "epss": epss,
            "in_kev": in_kev,
            "plugin_name": row["plugin_name"],
        })

    enriched.sort(key=lambda item: item["priority_score"], reverse=True)

    with open("remediation_queue.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=enriched[0].keys())
        writer.writeheader()
        writer.writerows(enriched)

    print(f"Loaded {len(findings)} total findings, {len(cve_rows)} had a CVE attached.")
    print(f"Wrote ranked list to remediation_queue.csv\n")
    for item in enriched:
        print(f"  [{item['priority_score']:.1f}] {item['cve']} - {item['plugin_name']} "
              f"(CVSS {item['cvss']}, EPSS {item['epss']}, KEV: {item['in_kev']})")


if __name__ == "__main__":
    main()
