# recon-pipeline — Robust Bash Recon Pipeline

A compact, robust Bash-based reconnaissance pipeline that automates:
- Subdomain enumeration (subfinder, assetfinder, amass)
- Host probing (httpx / curl fallback)
- URL collection (katana, waybackurls, gospider)
- JS/PHP extraction and quick analysis
- Wordlist-driven fuzzing with ffuf/dirsearch/gobuster

## Quick start
1. Edit config at top of `recon_pipeline.sh` (WORDLIST_BASE, CONCURRENCY, TIMEOUT).
2. Make executable:
   ```bash
   chmod +x recon_pipeline.sh
   
Copyright (c) 2025 Your AM/Bucky
