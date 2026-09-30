#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CYBER3 Scan — actualizează catalogul CISA KEV (Known Exploited Vulnerabilities).

Descarcă feed-ul oficial CISA și scrie un `kev.json` TRIM-uit (doar câmpurile folosite de c3vuln),
indexat pe CVE. Se rulează pe mașina de build / portal (NU pe senzor inline) și se livrează ca oui.txt.

  python3 c3kev_fetch.py            # scrie ./kev.json
  python3 c3kev_fetch.py --out /opt/cyber3/c3scan/kev.json
"""
import argparse, json, os, urllib.request

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "kev.json"))
    a = ap.parse_args()
    req = urllib.request.Request(URL, headers={"User-Agent": "CYBER3-Scan KEV updater"})
    raw = urllib.request.urlopen(req, timeout=40).read()
    cat = json.loads(raw)
    out = {}
    for v in cat.get("vulnerabilities", []):
        cve = v.get("cveID")
        if not cve:
            continue
        out[cve] = {
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", "")[:140],
            "added": v.get("dateAdded", ""),
            "ransomware": (v.get("knownRansomwareCampaignUse", "").lower() == "known"),
        }
    meta = {"_meta": {"released": cat.get("catalogVersion", ""), "count": len(out),
                      "dateReleased": cat.get("dateReleased", "")}}
    json.dump({**meta, **out}, open(a.out, "w"), ensure_ascii=False, separators=(",", ":"))
    print(f"[kev] {len(out)} CVE exploatate-în-lume → {a.out} ({os.path.getsize(a.out)//1024} KB)")

if __name__ == "__main__":
    main()
