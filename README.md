# neosec_passive_tool

**Overview**  
**neosec_passive_tool** is a safe, non‑intrusive passive reconnaissance tool designed to collect an initial attack surface for a target domain. It gathers subdomain candidates from **crt.sh**, performs lightweight DNS resolution using a small wordlist, issues HTTP HEAD checks to detect alive hosts, and captures simple TCP banners. The tool does **not** perform exploitation or aggressive port scanning.

---

## Features
- **crt.sh extraction** to collect subdomains observed in TLS certificates.  
- **Wordlist based subdomain discovery** using non‑intrusive DNS resolution.  
- **Lightweight HTTP checks** via HEAD requests to detect alive hosts and follow redirects.  
- **Simple banner grabbing** on common ports for basic server identification.  
- **Structured JSON outputs** for easy integration with other tools or reporting.  
- **Explicit permission prompt** before running to encourage legal and ethical use.

---

## Requirements
- **Operating system**: Linux recommended.  
- **Python**: Python 3.8 or newer.  
- **Python packages**: `requests`, `dnspython` (recommended), `tqdm` (optional).  
- **Optional tools** to improve coverage: `amass`, `subfinder`, `httpx`, `nuclei`, `nmap`. These are not required for the core passive functionality but are useful when available.

---

## Installation and Quick Start
**Create a Python virtual environment and install dependencies**
```bash
python3 -m venv venv
source venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install requests dnspython tqdm


Run the tool
source venv/bin/activate
python3 neosec_passive_tool.py --target example.com --output ./results


Install optional Go tools to extend capabilities
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"
go install github.com/owasp-amass/amass/v3/...@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest



Usage Examples
- Default passive scan
python3 neosec_passive_tool.py --target testphp.vulnweb.com --output ./results


- Use a custom wordlist and increase concurrency
python3 neosec_passive_tool.py --target example.com --output ./results --wordlist ./subdomains.txt --workers 40




