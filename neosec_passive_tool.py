#!/usr/bin/env python3
# neosec_passive_tool.py
# NeoSec Academy - Passive Recon Toolkit (safe, non-intrusive)
# Usage:
#   python3 neosec_passive_tool.py --target example.com --output results_dir
# Notes:
#   - This tool performs passive and non-intrusive checks only (crt.sh, DNS resolve,
#     simple wordlist subdomain discovery, HTTP HEAD checks).
#   - Active or intrusive scans are intentionally NOT implemented.
#   - Use only on targets you are authorized to test.

import os
import sys
import json
import argparse
import socket
import ssl
import time
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional dependencies: requests, dnspython
try:
    import requests
except Exception:
    requests = None

try:
    import dns.resolver
except Exception:
    dns = None

# Configuration
USER_AGENT = "NeoSecPassive/1.0 (+https://neosec.academy)"
REQUEST_TIMEOUT = 8
WORKERS = 20
DEFAULT_WORDLIST = [
    "www", "mail", "api", "dev", "test", "staging", "admin", "portal",
    "beta", "shop", "m", "mobile", "secure", "vpn", "smtp", "webmail",
    "ftp", "ns1", "ns2", "cdn", "images", "static", "docs", "support"
]

# Utilities
def ensure_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)

def save_json(obj, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def now_iso():
    return datetime.utcnow().isoformat() + "Z"

# Passive: crt.sh enumeration
def crtsh_enum(domain):
    results = []
    if not requests:
        return results
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {"User-Agent": USER_AGENT}
    try:
        r = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            names = set()
            for entry in data:
                nv = entry.get("name_value")
                if not nv:
                    continue
                for line in nv.splitlines():
                    line = line.strip().lower()
                    if line:
                        names.add(line)
            results = sorted(names)
    except Exception:
        pass
    return results

# Passive: simple wordlist-based subdomain discovery (non-intrusive)
def brute_subdomains(domain, wordlist=None, workers=WORKERS):
    if wordlist is None:
        wordlist = DEFAULT_WORDLIST
    candidates = [f"{w}.{domain}" for w in wordlist]
    alive = []
    def try_resolve(host):
        try:
            # Use socket.getaddrinfo (may be cached by system)
            infos = socket.getaddrinfo(host, None)
            if infos:
                return host
        except Exception:
            return None
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(try_resolve, h): h for h in candidates}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                alive.append(res)
    return sorted(set(alive))

# DNS resolution (A, AAAA, CNAME) using dnspython if available, fallback to socket
def resolve_host(host):
    out = {"host": host, "a": [], "aaaa": [], "cname": None}
    if dns:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5
        try:
            answers = resolver.resolve(host, "A")
            out["a"] = [r.to_text() for r in answers]
        except Exception:
            out["a"] = []
        try:
            answers = resolver.resolve(host, "AAAA")
            out["aaaa"] = [r.to_text() for r in answers]
        except Exception:
            out["aaaa"] = []
        try:
            answers = resolver.resolve(host, "CNAME")
            for r in answers:
                out["cname"] = str(r.target).rstrip(".")
                break
        except Exception:
            out["cname"] = None
    else:
        # fallback: try socket.getaddrinfo for A/AAAA
        try:
            infos = socket.getaddrinfo(host, None)
            addrs = set()
            for info in infos:
                addr = info[4][0]
                addrs.add(addr)
            out["a"] = sorted(list(addrs))
        except Exception:
            out["a"] = []
    return out

# HTTP HEAD check (lightweight)
def http_head_check(host, schemes=("https://", "http://")):
    results = []
    if not requests:
        return results
    headers = {"User-Agent": USER_AGENT}
    for scheme in schemes:
        url = scheme + host
        try:
            r = requests.head(url, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=True)
            results.append({"url": url, "status_code": r.status_code, "final_url": r.url})
            break
        except requests.exceptions.SSLError:
            # try without verify
            try:
                r = requests.head(url, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=False)
                results.append({"url": url, "status_code": r.status_code, "final_url": r.url, "ssl_verify": False})
                break
            except Exception:
                continue
        except Exception:
            continue
    return results

# Simple banner grab via TCP connect (port 80/443 optional)
def grab_banner(host, port=80, timeout=5):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # send minimal HTTP request for banner
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
                data = s.recv(1024)
                return data.decode(errors="ignore").strip()
            except Exception:
                return ""
    except Exception:
        return ""

# Main pipeline
def pipeline(domain, out_dir, wordlist=None, workers=WORKERS):
    ensure_dir(out_dir)
    meta = {"domain": domain, "started_at": now_iso()}
    # Normalize domain (strip protocol if provided)
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("://", 1)[1].strip().rstrip("/")
    meta["normalized_target"] = domain

    # 1) crt.sh passive enumeration
    crt = crtsh_enum(domain)
    meta["crtsh_count"] = len(crt)

    # 2) simple brute (wordlist)
    brute = brute_subdomains(domain, wordlist=wordlist, workers=workers)

    # 3) combine and dedupe
    combined = sorted(set([domain] + crt + brute))

    # 4) resolve hosts
    resolved = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(resolve_host, h): h for h in combined}
        for fut in as_completed(futures):
            resolved.append(fut.result())

    # 5) HTTP HEAD checks for alive hosts
    http_alive = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(http_head_check, r["host"]): r["host"] for r in resolved}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                for item in res:
                    http_alive.append(item)

    # 6) optional banner grabs (lightweight)
    banners = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {}
        for r in resolved:
            host = r["host"]
            # try common ports 80 and 443 (443 banner via TLS handshake not implemented here)
            futures[ex.submit(grab_banner, host, 80)] = (host, 80)
        for fut in as_completed(futures):
            host, port = futures[fut]
            b = fut.result()
            if b:
                banners.append({"host": host, "port": port, "banner": b})

    # Save outputs
    save_json({"crtsh": crt, "brute": brute, "combined": combined}, os.path.join(out_dir, "passive_enumeration.json"))
    save_json(resolved, os.path.join(out_dir, "resolved.json"))
    save_json(http_alive, os.path.join(out_dir, "http_alive.json"))
    save_json(banners, os.path.join(out_dir, "banners.json"))

    meta["http_alive_count"] = len(http_alive)
    meta["finished_at"] = now_iso()
    save_json(meta, os.path.join(out_dir, "meta.json"))
    return True

# CLI
def parse_args():
    p = argparse.ArgumentParser(description="NeoSec Academy - Passive Recon Toolkit (safe)")
    p.add_argument("--target", required=True, help="Target domain (e.g., example.com)")
    p.add_argument("--output", required=True, help="Output directory")
    p.add_argument("--wordlist", help="Optional path to newline wordlist for subdomain brute")
    p.add_argument("--workers", type=int, default=WORKERS, help="Number of concurrent workers")
    return p.parse_args()

def load_wordlist(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            return lines
    except Exception:
        return None

def main():
    args = parse_args()
    target = args.target.strip()
    outdir = args.output.strip()
    ensure_dir(outdir)

    # Legal acknowledgement (explicit)
    print("NeoSec Academy Passive Recon Toolkit")
    print("This tool performs passive, non-intrusive checks only.")
    ack = input("Do you have permission to gather passive information about this target? Type 'yes' to continue: ").strip().lower()
    if ack != "yes":
        print("Acknowledgement not provided. Exiting.")
        sys.exit(1)

    wordlist = None
    if args.wordlist:
        wl = load_wordlist(args.wordlist)
        if wl:
            wordlist = wl
        else:
            print("Warning: could not load wordlist, using default small list.")

    try:
        pipeline(target, outdir, wordlist=wordlist, workers=args.workers)
        print("Done. Results saved in:", outdir)
    except KeyboardInterrupt:
        print("Interrupted by user.")
    except Exception as e:
        print("Error:", str(e))

if __name__ == "__main__":
    main()


