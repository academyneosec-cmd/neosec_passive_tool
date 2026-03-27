# setup_neosec_all.sh
# واحد ملف يجهز الأداة ويثبت الاعتماديات الشائعة (Python + Go tools + system tools)
# Usage:
#   sudo bash setup_neosec_all.sh /opt/neosec
# If no target dir provided, defaults to /opt/neosec
# ملاحظة: شغّل هذا السكربت على توزيعات Debian/Ubuntu/Kali. قد تحتاج لتعديل لأوبنتو/أخرى.

set -euo pipefail

# ---------------------------
# Configuration
# ---------------------------
INSTALL_DIR="${1:-/opt/neosec}"
PY_FILE="${INSTALL_DIR}/neosec_passive_tool.py"
VENV_DIR="${INSTALL_DIR}/venv"
INSTALL_SH="${INSTALL_DIR}/install_deps.log"
GOPATH_DEFAULT="$HOME/go"
GO_TOOLS=(
  "github.com/owasp-amass/amass/v3/...@latest"
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "github.com/ffuf/ffuf@latest"
)
PY_PKGS=("requests" "dnspython" "tqdm")
SYS_PKGS=(git curl wget build-essential libldns-dev nmap sqlmap gobuster masscan python3-venv python3-pip)

# ---------------------------
# Helpers
# ---------------------------
info(){ printf "\e[1;34m[INFO]\e[0m %s\n" "$*"; }
warn(){ printf "\e[1;33m[WARN]\e[0m %s\n" "$*"; }
err(){ printf "\e[1;31m[ERROR]\e[0m %s\n" "$*"; exit 1; }

# ---------------------------
# Prepare directories
# ---------------------------
info "Creating install directory: ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"
chown "$(whoami):$(whoami)" "${INSTALL_DIR}"

# ---------------------------
# Write the Python tool file
# ---------------------------
info "Writing Python passive tool to ${PY_FILE}"
cat > "${PY_FILE}" <<'PY'
#!/usr/bin/env python3
# neosec_passive_tool.py
# NeoSec Academy - Passive Recon Toolkit (safe, non-intrusive)
# Usage:
#   python3 neosec_passive_tool.py --target example.com --output results_dir

import os
import sys
import json
import argparse
import socket
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except Exception:
    requests = None

try:
    import dns.resolver
except Exception:
    dns = None

USER_AGENT = "NeoSecPassive/1.0 (+https://neosec.academy)"
REQUEST_TIMEOUT = 8
WORKERS = 20
DEFAULT_WORDLIST = [
    "www", "mail", "api", "dev", "test", "staging", "admin", "portal",
    "beta", "shop", "m", "mobile", "secure", "vpn", "smtp", "webmail",
    "ftp", "ns1", "ns2", "cdn", "images", "static", "docs", "support"
]

def ensure_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)

def save_json(obj, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def now_iso():
    return datetime.utcnow().isoformat() + "Z"

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

def brute_subdomains(domain, wordlist=None, workers=WORKERS):
    if wordlist is None:
        wordlist = DEFAULT_WORDLIST
    candidates = [f"{w}.{domain}" for w in wordlist]
    alive = []
    def try_resolve(host):
        try:
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
            try:
                r = requests.head(url, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=False)
                results.append({"url": url, "status_code": r.status_code, "final_url": r.url, "ssl_verify": False})
                break
            except Exception:
                continue
        except Exception:
            continue
    return results

def grab_banner(host, port=80, timeout=5):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
                data = s.recv(1024)
                return data.decode(errors="ignore").strip()
            except Exception:
                return ""
    except Exception:
        return ""

def pipeline(domain, out_dir, wordlist=None, workers=WORKERS):
    ensure_dir(out_dir)
    meta = {"domain": domain, "started_at": now_iso()}
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("://", 1)[1].strip().rstrip("/")
    meta["normalized_target"] = domain

    crt = crtsh_enum(domain)
    meta["crtsh_count"] = len(crt)

    brute = brute_subdomains(domain, wordlist=wordlist, workers=workers)

    combined = sorted(set([domain] + crt + brute))

    resolved = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(resolve_host, h): h for h in combined}
        for fut in as_completed(futures):
            resolved.append(fut.result())

    http_alive = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(http_head_check, r["host"]): r["host"] for r in resolved}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                for item in res:
                    http_alive.append(item)

    banners = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {}
        for r in resolved:
            host = r["host"]
            futures[ex.submit(grab_banner, host, 80)] = (host, 80)
        for fut in as_completed(futures):
            host, port = futures[fut]
            b = fut.result()
            if b:
                banners.append({"host": host, "port": port, "banner": b})

    save_json({"crtsh": crt, "brute": brute, "combined": combined}, os.path.join(out_dir, "passive_enumeration.json"))
    save_json(resolved, os.path.join(out_dir, "resolved.json"))
    save_json(http_alive, os.path.join(out_dir, "http_alive.json"))
    save_json(banners, os.path.join(out_dir, "banners.json"))

    meta["http_alive_count"] = len(http_alive)
    meta["finished_at"] = now_iso()
    save_json(meta, os.path.join(out_dir, "meta.json"))
    return True

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

    print("NeoSec Academy Passive Recon Toolkit")
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
PY

chmod +x "${PY_FILE}"

# ---------------------------
# Install system packages
# ---------------------------
info "Installing system packages (this may take a while)..."
if command -v apt >/dev/null 2>&1; then
  apt update -y
  apt install -y "${SYS_PKGS[@]}"
else
  warn "apt not found. Please install system packages manually: ${SYS_PKGS[*]}"
fi

# ---------------------------
# Setup Python venv and install Python packages
# ---------------------------
info "Creating Python virtual environment at ${VENV_DIR}"
python3 -m venv "${VENV_DIR}"
# shellcheck disable=SC1090
source "${VENV_DIR}/bin/activate"
info "Upgrading pip and installing Python packages: ${PY_PKGS[*]}"
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade "${PY_PKGS[@]}"

# ---------------------------
# Install Go and Go tools
# ---------------------------
if ! command -v go >/dev/null 2>&1; then
  info "Go not found. Installing golang (apt)..."
  if command -v apt >/dev/null 2>&1; then
    apt install -y golang
  else
    warn "Cannot install Go automatically. Please install Go manually and re-run the script."
  fi
fi

export GOPATH="${GOPATH_DEFAULT}"
export PATH="${PATH}:${GOPATH}/bin"
mkdir -p "${GOPATH}/bin"

info "Installing Go-based tools (amass, subfinder, httpx, nuclei, dnsx, ffuf)..."
for t in "${GO_TOOLS[@]}"; do
  info "  - go install ${t}"
  /usr/bin/env go install "${t}" || warn "go install failed for ${t}"
done

# ---------------------------
# massdns (optional) - build from source
# ---------------------------
if ! command -v massdns >/dev/null 2>&1; then
  info "Installing massdns from source..."
  if [ ! -d "/opt/massdns" ]; then
    git clone https://github.com/blechschmidt/massdns.git /opt/massdns || warn "git clone massdns failed"
    pushd /opt/massdns >/dev/null || true
    make || warn "make massdns failed"
    cp bin/massdns /usr/local/bin/ || warn "copy massdns failed"
    popd >/dev/null || true
  else
    info "massdns already cloned at /opt/massdns"
  fi
fi

# ---------------------------
# Update nuclei templates
# ---------------------------
if command -v nuclei >/dev/null 2>&1; then
  info "Updating nuclei templates..."
  nuclei -update-templates || warn "nuclei template update failed"
fi

# ---------------------------
# Final checks and PATH hints
# ---------------------------
info "Final verification of installed tools:"
for tool in amass subfinder httpx nuclei dnsx ffuf nmap sqlmap masscan gobuster massdns; do
  if command -v "${tool}" >/dev/null 2>&1; then
    printf "  - %s: %s\n" "${tool}" "$(command -v "${tool}")"
  else
    printf "  - %s: NOT FOUND\n" "${tool}"
  fi
done

# Write a small README
cat > "${INSTALL_DIR}/README.txt" <<EOF
NeoSec All-in-One Setup
Directory: ${INSTALL_DIR}

Python tool:
  ${PY_FILE}

Virtualenv:
  ${VENV_DIR} (activate with: source ${VENV_DIR}/bin/activate)

To run the passive tool:
  source ${VENV_DIR}/bin/activate
  python3 ${PY_FILE} --target example.com --output ${INSTALL_DIR}/results

Installed Go tools (if successful):
  amass, subfinder, httpx, nuclei, dnsx, ffuf

Installed system tools (if successful):
  nmap, masscan, sqlmap, gobuster, massdns (if built)

Notes:
  - Use active/intrusive tools only with explicit written permission.
  - If some tools show NOT FOUND, install them manually or ensure GOPATH/bin is in PATH.
EOF

info "Installation complete. See ${INSTALL_DIR}/README.txt for usage."
info "If some tools are NOT FOUND, add ${GOPATH}/bin to your PATH or install missing tools manually."

# deactivate venv in script context
deactivate 2>/dev/null || true

exit 0


