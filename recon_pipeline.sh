#!/usr/bin/env bash
# recon_pipeline.sh — final robust pipeline
# Usage: ./recon_pipeline.sh example.com
# Requirements: subfinder, assetfinder, amass (optional), httpx (optional), katana (optional),
# waybackurls (optional), gospider (optional), ffuf/dirsearch/gobuster (optional), linkfinder (optional)
# Wordlists folder (required): /root/wordlists/assetnote/data/

set -euo pipefail
IFS=$'\n\t'

###########################
# CONFIG (edit if needed) #
###########################
WORDLIST_BASE="/root/wordlists/assetnote/data"
CONCURRENCY="${CONCURRENCY:-50}"
TIMEOUT="${TIMEOUT:-10}"
###########################

info(){ echo -e "[*] $*"; }
warn(){ echo -e "[!] $*"; }
err(){ echo -e "[ERROR] $*" >&2; exit 1; }

# input
TARGET_IN="${1:-}"
if [ -z "$TARGET_IN" ]; then
  read -rp "Enter target domain or URL (e.g., example.com or https://example.com): " TARGET_IN
fi

# sanitize domain: strip scheme, leading www, trailing slash
DOMAIN=$(echo "$TARGET_IN" | sed -E 's#^https?://##i; s#^www\.##i; s#/$##')
if [ -z "$DOMAIN" ]; then err "Couldn't parse domain from input: $TARGET_IN"; fi

# workspace
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
WORKDIR="$(pwd)/recon_workspace_${DOMAIN}_$TIMESTAMP"
mkdir -p "$WORKDIR"
info "Workspace: $WORKDIR"

# helper: append + dedupe (use anew if available)
append_dedupe() {
  local in="$1" out="$2"
  if command -v anew >/dev/null 2>&1; then
    cat "$in" | anew >> "$out" || true
  else
    cat "$in" >> "$out"
    sort -u "$out" -o "$out" || true
  fi
}

# ---------- SUBDOMAIN ENUM ----------
info "Step 1: Subdomain enumeration"
SUBS_RAW="$WORKDIR/subs_raw.txt"
: > "$SUBS_RAW"

if command -v subfinder >/dev/null 2>&1; then
  info "running subfinder..."
  subfinder -d "$DOMAIN" -silent -recursive >> "$SUBS_RAW" 2>/dev/null || true
fi

if command -v assetfinder >/dev/null 2>&1; then
  info "running assetfinder..."
  echo "$DOMAIN" | assetfinder --subs-only >> "$SUBS_RAW" 2>/dev/null || true
fi

if command -v amass >/dev/null 2>&1; then
  info "running amass (passive)..."
  amass enum -passive -d "$DOMAIN" -o "$WORKDIR/amass.txt" 2>/dev/null || true
  if [ -f "$WORKDIR/amass.txt" ]; then
    cat "$WORKDIR/amass.txt" >> "$SUBS_RAW" || true
  fi
fi

ALLSUBS="$WORKDIR/allsubs.txt"
: > "$ALLSUBS"
if [ -s "$SUBS_RAW" ]; then
  append_dedupe "$SUBS_RAW" "$ALLSUBS"
fi

# always include base domain as fallback target
echo "$DOMAIN" >> "$ALLSUBS"
sort -u "$ALLSUBS" -o "$ALLSUBS"

info "Total subdomains found (incl. base): $(wc -l < "$ALLSUBS")"

# ---------- PROBE (httpx with robust fallbacks) ----------
info "Step 2: Probing hosts (httpx/curl fallback)"
HTTPX_OUT="$WORKDIR/httpx_all.txt"
LIVE_SUBS="$WORKDIR/live_subs.txt"
: > "$HTTPX_OUT"
: > "$LIVE_SUBS"

# Try multiple httpx invocation styles
probe_httpx_try_lflag() {
  # some httpx versions support -l <file>
  if httpx -h 2>&1 | grep -q -- '-l'; then
    info "httpx supports -l -> using: httpx -l <file>"
    httpx -l "$ALLSUBS" -silent -status-code -timeout "$TIMEOUT" -threads "$CONCURRENCY" -o "$HTTPX_OUT" 2>/dev/null || true
    return 0
  fi
  return 1
}

probe_httpx_try_stdin() {
  # pipe via stdin
  info "Trying: cat file | httpx (stdin mode)"
  if cat "$ALLSUBS" | httpx -silent -status-code -timeout "$TIMEOUT" -threads "$CONCURRENCY" -o "$HTTPX_OUT" 2>/dev/null; then
    return 0
  fi
  # some old httpx may not support -status-code
  if cat "$ALLSUBS" | httpx -silent -timeout "$TIMEOUT" -threads "$CONCURRENCY" -o "$HTTPX_OUT" 2>/dev/null; then
    return 0
  fi
  return 1
}

probe_httpx_per_host() {
  info "Trying per-host httpx calls (xargs, positional URL)"
  if ! command -v httpx >/dev/null 2>&1; then
    return 1
  fi
  : > "$HTTPX_OUT"
  # xargs: try https then http for each host
  xargs -a "$ALLSUBS" -P "$CONCURRENCY" -I{} sh -c \
    'host="{}"; echo "[probe] $host" >> "'"$HTTPX_OUT"'"; \
     httpx "https://$host" -silent -status-code -timeout '"$TIMEOUT"' 2>> "'"$HTTPX_OUT"'" || \
     httpx "http://$host" -silent -status-code -timeout '"$TIMEOUT"' 2>> "'"$HTTPX_OUT"'"' || true
  return 0
}

probe_curl_fallback() {
  info "Falling back to curl for probing"
  : > "$HTTPX_OUT"
  # use parallel curl attempts
  awk '{print}' "$ALLSUBS" | xargs -P "$CONCURRENCY" -I{} sh -c \
    'printf "%s " "{}"; \
     curl -k -s -o /dev/null -w "%{http_code}\n" "https://{}" || curl -k -s -o /dev/null -w "%{http_code}\n" "http://{}"' \
    >> "$HTTPX_OUT" || true
  return 0
}

if command -v httpx >/dev/null 2>&1; then
  if probe_httpx_try_lflag; then
    info "Used httpx -l"
  elif probe_httpx_try_stdin; then
    info "Used httpx via stdin"
  elif probe_httpx_per_host; then
    info "Used httpx per-host fallback"
  else
    probe_curl_fallback
  fi
else
  warn "httpx not installed — using curl fallback"
  probe_curl_fallback
fi

# Normalize extraction of live targets from HTTPX_OUT:
# prefer extracting http(s)://... patterns; else extract tokens that look like host/url
if grep -qE 'https?://' "$HTTPX_OUT" 2>/dev/null; then
  grep -Eo "https?://[^ ]+" "$HTTPX_OUT" | sed 's/\/$//' | sort -u > "$LIVE_SUBS" || true
else
  # lines like: 200 https://domain or [probe] domain
  awk '{for(i=1;i<=NF;i++) if ($i ~ /^https?:\/\//) print $i; else if ($i ~ /^[0-9]{3}$/) next; else print $i}' "$HTTPX_OUT" \
    | sed 's/^\[probe\] //' | sed 's/\/$//' | sort -u > "$LIVE_SUBS" || true
fi

# if still empty, copy allsubs
if [ ! -s "$LIVE_SUBS" ]; then
  warn "No probe output parsed — using allsubs as live targets"
  cp "$ALLSUBS" "$LIVE_SUBS"
fi

info "Live targets count: $(wc -l < "$LIVE_SUBS")"

# ---------- URL COLLECTION ----------
info "Step 3: URL collection (katana / waybackurls / gospider if available)"
KATANA_OUT="$WORKDIR/katana.txt"
WAYBACK_OUT="$WORKDIR/wayback.txt"
GOSPIDER_OUT="$WORKDIR/gospider.txt"
: > "$KATANA_OUT" ; : > "$WAYBACK_OUT" ; : > "$GOSPIDER_OUT"

if command -v katana >/dev/null 2>&1; then
  info "running katana..."
  katana -list "$LIVE_SUBS" -o "$KATANA_OUT" -silent 2>/dev/null || true
fi

if command -v waybackurls >/dev/null 2>&1; then
  info "running waybackurls..."
  cat "$LIVE_SUBS" | waybackurls >> "$WAYBACK_OUT" 2>/dev/null || true
fi

if command -v gospider >/dev/null 2>&1; then
  info "running gospider..."
  # gospider -S accepts newline list; output to directory then extract URLs
  gospider -S "$LIVE_SUBS" -t "$CONCURRENCY" -a -sitemap -o "$WORKDIR/gospider_raw" 2>/dev/null || true
  find "$WORKDIR/gospider_raw" -type f -name "*.txt" -exec cat {} + | grep -Eo "https?://[^\"' ]+" >> "$GOSPIDER_OUT" || true
fi

ALL_URLS_RAW="$WORKDIR/urls_raw.txt"
: > "$ALL_URLS_RAW"
cat "$KATANA_OUT" "$WAYBACK_OUT" "$GOSPIDER_OUT" | sed 's/\/$//' >> "$ALL_URLS_RAW" || true
# ensure base hosts are included as URLs
awk '{print}' "$LIVE_SUBS" | sed -E 's#^([^/:]+)$#https://\1#' >> "$ALL_URLS_RAW" || true
sort -u "$ALL_URLS_RAW" -o "$WORKDIR/allurls.txt"

info "Total URLs collected: $(wc -l < "$WORKDIR/allurls.txt")"

# ---------- EXTRACT .js and .php ----------
info "Step 4: Extract .js and .php files"
JS_OUT="$WORKDIR/js.txt"
PHP_OUT="$WORKDIR/php.txt"
grep -Eo "https?://[^ ]+\.js(\?|$)" "$WORKDIR/allurls.txt" | sed 's/[?].*$//' | sort -u > "$JS_OUT" || true
grep -Eo "https?://[^ ]+\.php(\?|$)" "$WORKDIR/allurls.txt" | sed 's/[?].*$//' | sort -u > "$PHP_OUT" || true
info "JS files: $(wc -l < "$JS_OUT") | PHP files: $(wc -l < "$PHP_OUT")"

# ---------- JS QUICK ANALYSIS ----------
info "Step 5: JS quick analysis (linkfinder or grep patterns)"
JS_SECRETS="$WORKDIR/js_secrets.txt"
: > "$JS_SECRETS"

if command -v linkfinder >/dev/null 2>&1; then
  info "running linkfinder on JS files..."
  cat "$JS_OUT" | xargs -n1 -P8 -I{} sh -c 'python3 $(which linkfinder) -i "{}" -o cli' >> "$JS_SECRETS" 2>/dev/null || true
else
  # fallback: download js and grep common patterns
  info "linkfinder not found — using curl+grep fallback"
  cat "$JS_OUT" | xargs -n1 -P8 -I{} sh -c 'curl -s --max-time 10 "{}" || true' \
    | grep -Eo "api[_-]?[a-zA-Z0-9/._-]{3,}|AIza[0-9A-Za-z-_]{35}|Bearer [A-Za-z0-9\-\._~+/]+=*|access_token=[^&\"']+" \
    | sort -u >> "$JS_SECRETS" || true
fi
info "JS secrets/endpoints found: $(wc -l < "$JS_SECRETS")"

# ---------- FUZZING ----------
info "Step 6: Fuzzing (ffuf / dirsearch / gobuster) using all wordlists under $WORDLIST_BASE"
FUZZ_DIR="$WORKDIR/fuzz"
mkdir -p "$FUZZ_DIR"

# collect wordlist files
if [ -d "$WORDLIST_BASE" ]; then
  mapfile -t WORDLIST_FILES < <(find "$WORDLIST_BASE" -type f | sort)
else
  warn "Wordlist base not found: $WORDLIST_BASE — skipping fuzzing"
  WORDLIST_FILES=()
fi

# target base url (ensure scheme)
TARGET_URL="$DOMAIN"
if [[ "$TARGET_URL" != http* ]]; then
  TARGET_URL="https://$TARGET_URL"
fi

for wl in "${WORDLIST_FILES[@]:-}"; do
  info "Fuzzing with: $wl"
  if command -v ffuf >/dev/null 2>&1; then
    ffuf -u "${TARGET_URL}/FUZZ" -w "$wl" -mc 200 -t "$CONCURRENCY" -o "$FUZZ_DIR/ffuf_$(basename "$wl").json" -of json || true
  fi
  if command -v dirsearch >/dev/null 2>&1; then
    # dirsearch may be in tools dir — try to run it by path if available in PATH
    dirsearch -u "$TARGET_URL" -w "$wl" -e php,html,js,txt -t "$CONCURRENCY" -o "$FUZZ_DIR/dirsearch_$(basename "$wl").txt" || true
  fi
  if command -v gobuster >/dev/null 2>&1; then
    gobuster dir -u "$TARGET_URL" -w "$wl" -t "$CONCURRENCY" -o "$FUZZ_DIR/gobuster_$(basename "$wl").txt" || true
  fi
done

info "Fuzzing finished. Results in: $FUZZ_DIR (if tools present)"

# ---------- FINAL SUMMARY ----------
info "Packaging summary -> $WORKDIR/summary.txt"
{
  echo "Target: $DOMAIN"
  echo "Workspace: $WORKDIR"
  echo ""
  echo "Subdomains (deduped): $(wc -l < "$ALLSUBS" 2>/dev/null || echo 0)"
  echo "Live targets: $(wc -l < "$LIVE_SUBS" 2>/dev/null || echo 0)"
  echo "Total URLs: $(wc -l < "$WORKDIR/allurls.txt" 2>/dev/null || echo 0)"
  echo "JS files: $(wc -l < "$JS_OUT" 2>/dev/null || echo 0)"
  echo "PHP files: $(wc -l < "$PHP_OUT" 2>/dev/null || echo 0)"
  echo "JS secrets/endpoints: $(wc -l < "$JS_SECRETS" 2>/dev/null || echo 0)"
  echo ""
  echo "Files saved under: $WORKDIR"
} > "$WORKDIR/summary.txt"

info "Done. Check: $WORKDIR"
