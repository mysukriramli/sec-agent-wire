#!/usr/bin/env python3
"""
Autonomous Security Exploit Wire for AI Coding Agents
Ingests CISA KEV and GitHub security alerts, cleans them, and outputs
raw endpoints consumable directly by LLMs.
"""

import os
import json
import logging
from datetime import datetime, timezone
import requests
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

DATA_DIR = "data"
ARCHIVE_DIR = os.path.join(DATA_DIR, "archive")
os.makedirs(ARCHIVE_DIR, exist_ok=True)

TODAY_JSON = os.path.join(DATA_DIR, "today.json")
LLMS_TXT = os.path.join(DATA_DIR, "llms.txt")


class VulnerabilityRecord(BaseModel):
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    known_ransomware_use: str


def fetch_cisa_exploits():
    """Fetches the official US CISA Known Exploited Vulnerabilities catalog (Free JSON)."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        res = requests.get(url, timeout=15)
        res.raise_for_status()
        data = res.json()
        
        # Take the 30 most recently added active exploits
        vulnerabilities = data.get("vulnerabilities", [])[-30:]
        records = []
        for v in reversed(vulnerabilities):
            records.append(VulnerabilityRecord(
                cve_id=v.get("cveID", ""),
                vendor_project=v.get("vendorProject", "Unknown"),
                product=v.get("product", "Unknown"),
                vulnerability_name=v.get("vulnerabilityName", ""),
                date_added=v.get("dateAdded", ""),
                short_description=v.get("shortDescription", ""),
                required_action=v.get("requiredAction", ""),
                known_ransomware_use=v.get("knownRansomwareCampaignUse", "Unknown")
            ))
        return records
    except Exception as e:
        logging.error(f"Failed to fetch CISA catalog: {e}")
        return []


def write_endpoints(records):
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    date_str = now.strftime("%Y-%m-%d")

    # 1. Output today.json
    payload = {
        "metadata": {
            "generated_at": now_iso,
            "total_active_exploits": len(records),
            "feed_source": "CISA Known Exploited Vulnerabilities Catalog",
            "schema_version": "1.0.0"
        },
        "exploits": [r.model_dump() for r in records]
    }
    with open(TODAY_JSON, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    # 2. Output llms.txt (token-efficient markdown for LLM context injection)
    lines = [
        "# Active Security Exploits & Zero-Day Wire",
        f"> Last updated: {now_iso} | Source: CISA KEV Catalog",
        "",
        "## Critical Active Exploits in the Wild"
    ]
    for r in records:
        lines.append(
            f"- **[{r.cve_id}] {r.vendor_project} - {r.product}**\n"
            f"  - Vulnerability: {r.vulnerability_name}\n"
            f"  - Date Added: {r.date_added} | Ransomware Linked: {r.known_ransomware_use}\n"
            f"  - Action: {r.required_action}\n"
            f"  - Summary: {r.short_description}\n"
        )

    with open(LLMS_TXT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    # 3. Archive daily snapshot
    month_dir = os.path.join(ARCHIVE_DIR, now.strftime("%Y"), now.strftime("%m"))
    os.makedirs(month_dir, exist_ok=True)
    with open(os.path.join(month_dir, f"{date_str}.json"), "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    logging.info(f"Successfully generated endpoints with {len(records)} active exploits.")


if __name__ == "__main__":
    exploits = fetch_cisa_exploits()
    if exploits:
        write_endpoints(exploits)
