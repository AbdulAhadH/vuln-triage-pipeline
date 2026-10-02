#!/usr/bin/env python3
"""
nessus_export.py

Nessus Essentials blocks the "Export" button in the web UI (CSV/PDF/HTML
reports are a Nessus Professional feature). This script gets around that
by talking directly to Nessus's own local API -- the same API the web UI
itself uses -- and writes the results out to a clean CSV.

SETUP
-----
1. Install the one dependency this needs:
     pip install requests --break-system-packages

2. In the Nessus web UI: click your username (top right) -> My Account
   -> API Keys tab -> Generate. Copy the Access Key and Secret Key.

3. Set them as environment variables (do NOT hardcode them in this file,
   especially if this repo is going on GitHub):
     export NESSUS_ACCESS_KEY="your_access_key_here"
     export NESSUS_SECRET_KEY="your_secret_key_here"

4. Run it:
     python3 nessus_export.py

   By default it looks for a scan named "Lab VM Scan". If yours is named
   differently, either rename it in Nessus or change SCAN_NAME below.

OUTPUT
------
Writes nessus_findings.csv in the current folder, one row per finding,
with columns: host, plugin_id, plugin_name, severity, cvss_base_score,
cvss3_base_score, risk_factor, cve, description, solution.

That CSV is what the enrichment script (cvss/epss/kev pipeline) reads in.
"""

import os
import sys
import csv
import time

import requests
import urllib3

# Nessus uses a self-signed certificate for its local web UI, so we have
# to tell requests not to complain about that -- this is only talking to
# localhost, so it's not the same risk as disabling verification on a
# real internet-facing site.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

NESSUS_URL = "https://localhost:8834"
SCAN_NAME = "Lab VM Scan"          # change this if your scan has a different name
OUTPUT_CSV = "nessus_findings.csv"

ACCESS_KEY = os.environ.get("NESSUS_ACCESS_KEY")
SECRET_KEY = os.environ.get("NESSUS_SECRET_KEY")

if not ACCESS_KEY or not SECRET_KEY:
    print("ERROR: NESSUS_ACCESS_KEY and/or NESSUS_SECRET_KEY are not set.")
    print("Run these first (with your real keys):")
    print('  export NESSUS_ACCESS_KEY="your_access_key"')
    print('  export NESSUS_SECRET_KEY="your_secret_key"')
    sys.exit(1)

HEADERS = {
    "X-ApiKeys": f"accessKey={ACCESS_KEY}; secretKey={SECRET_KEY}",
    "Content-Type": "application/json",
}


def get(path, params=None):
    """Small wrapper around requests.get with our auth headers baked in."""
    resp = requests.get(f"{NESSUS_URL}{path}", headers=HEADERS, params=params, verify=False)
    resp.raise_for_status()
    return resp.json()


def find_scan_id(name):
    data = get("/scans")
    scans = data.get("scans") or []
    for scan in scans:
        if scan.get("name") == name:
            return scan["id"]
    available = [s.get("name") for s in scans]
    raise SystemExit(
        f"Could not find a scan named '{name}'.\nScans that DO exist: {available}\n"
        f"Either rename your scan to match, or edit SCAN_NAME in this script."
    )


def extract_cves(plugin_attributes):
    """CVE references live in a nested, slightly awkward spot in the API response."""
    cves = []
    ref_info = plugin_attributes.get("ref_information", {})
    refs = ref_info.get("ref", [])
    if isinstance(refs, dict):
        refs = [refs]
    for ref in refs:
        if isinstance(ref, dict) and ref.get("name", "").lower() == "cve":
            values = ref.get("values", {})
            val = values.get("value") if isinstance(values, dict) else values
            if isinstance(val, list):
                cves.extend(val)
            elif val:
                cves.append(val)
    return cves


def main():
    scan_id = find_scan_id(SCAN_NAME)
    print(f"Found scan '{SCAN_NAME}' (id={scan_id})")

    scan_detail = get(f"/scans/{scan_id}")
    hosts = scan_detail.get("hosts", [])
    print(f"Hosts in this scan: {len(hosts)}")

    rows = []
    for host in hosts:
        host_id = host["host_id"]
        hostname = host.get("hostname", "")
        print(f"  Reading findings for host {hostname} ...")
        host_detail = get(f"/scans/{scan_id}/hosts/{host_id}")

        for vuln in host_detail.get("vulnerabilities", []):
            plugin_id = vuln["plugin_id"]
            try:
                plugin_detail = get(f"/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}")
            except requests.HTTPError as e:
                print(f"    (skipping plugin {plugin_id}, request failed: {e})")
                continue

            info = plugin_detail.get("info", {})
            plugin_desc = info.get("plugindescription", {})
            attrs = plugin_desc.get("pluginattributes", {})
            risk_info = attrs.get("risk_information", {})

            rows.append({
                "host": hostname,
                "plugin_id": plugin_id,
                "plugin_name": vuln.get("plugin_name", ""),
                "severity": vuln.get("severity", ""),
                "cvss_base_score": risk_info.get("cvss_base_score", ""),
                "cvss3_base_score": risk_info.get("cvss3_base_score", ""),
                "risk_factor": risk_info.get("risk_factor", ""),
                "cve": ";".join(extract_cves(attrs)),
                "description": (attrs.get("description", "") or "").replace("\n", " ").strip(),
                "solution": (attrs.get("solution", "") or "").replace("\n", " ").strip(),
            })

            # Be gentle with the local API -- there's no real need to hammer it.
            time.sleep(0.05)

    if not rows:
        print("No findings came back. Double-check the scan is Completed and has results in the UI.")
        sys.exit(1)

    fieldnames = list(rows[0].keys())
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nDone. Wrote {len(rows)} findings to {OUTPUT_CSV}")
    cve_rows = [r for r in rows if r["cve"]]
    print(f"Of those, {len(cve_rows)} rows have at least one CVE attached -- "
          f"that's your raw material for the enrichment step.")


if __name__ == "__main__":
    main()
