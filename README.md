# OSINT Platform (Alpha Release)

High-performance, resource-centric, passive Open-Source Intelligence (OSINT) platform engineered in Rust. Combines a resilient Command Line Interface (CLI) and an interactive force-directed graph web panel in a single self-contained binary.

## Key Capabilities

- **Zero Active Intrusion**: 100% passive intelligence gathered strictly from public records, transparency logs, and authoritative APIs. No active port scanning, credential stuffing, or exploit attempts.
- **Deep Pivot Graph Engine**: Force-directed multi-depth entity relationship discovery with smart collision avoidance, degree centrality ranking, and indicator clustering.
- **Forensic Integrity Verification**: Every investigation finding is hashed with SHA-256 upon storage; tamper detection warns if database records are modified externally.
- **Multi-Factor Correlation**: Discovers shared Google Analytics/Tag Manager IDs, AdSense publisher codes, Shodan favicon MurmurHash3, nameservers, and certificate transparency trails.
- **Fullstack Mobile & Desktop Web Panel**: Embedded HTML5 Canvas with pinch-to-zoom, single-touch pan, responsive layout breakpoints, and bilingual (English/Turkish) support.
- **Strict Network & Storage Hardening**: Built-in SSRF defense filtering RFC 1918, RFC 3927, link-local, loopback, and documentation subnets; atomic file writes with POSIX 0600/0700 file permissions and symlink rejection.

---

## Architecture & Modules

| Command | Capability & Data Sources |
|---|---|
| `osint domain <target>` | DNS records (A, AAAA, MX, NS, TXT, SOA, CAA), RDAP registration, crt.sh certificate transparency subdomains, email security evaluation (SPF, DMARC, DKIM). |
| `osint ip <target>` | IP geolocation, Autonomous System (ASN), reverse PTR DNS, Bogon/private IP checks, passive service detection via Shodan InternetDB. |
| `osint web <target>` | HTTP headers, tech fingerprinting (CMS/frameworks), missing security headers analysis, tracking IDs (UA-, G-, GTM-, ca-pub-), favicon mmh3 hash, robots.txt, security.txt, Wayback machine status. |
| `osint user <target>` | Multi-platform username enumeration, account existence validation, variation suggestions. |
| `osint email <target>` | MX deliverability, Gravatar avatar profile lookup, disposable/free webmail detection, HaveIBeenPwned breach lookup (API key optional). |
| `osint phone <target>` | E.164 normalization, country validation, carrier/line type estimation, reverse lookup pivots. |
| `osint media <file>` | EXIF metadata extraction, GPS coordinate calculation, PDF & OOXML (DOCX/XLSX/PPTX) author metadata, cryptographic digests (MD5, SHA-1, SHA-256), VirusTotal hash scan (optional). |
| `osint history <target>` | Historic TLS certificate analysis, Wayback CDX machine endpoints and parameter discovery, archived email harvesting, GitHub code search (token optional). |
| `osint harita <files...>` | Batch extracts GPS coordinates from media files and outputs a standardized GeoJSON FeatureCollection. |
| `osint pivot <type> <seed>` | Force-directed entity pivot generator exploring connections across domains, IPs, URLs, emails, and usernames up to depth 4. |
| `osint imza-guncelle` | Synchronizes username signature patterns from WhatsMyName project (over 700 online platforms). |
| `osint vaka <cmd>` | Case management with SQLite backend and tamper-evident SHA-256 integrity verification. |

---

## Installation & Deployment

### Prerequisites

- Rust 1.75+ toolchain (`rustup` recommended)
- `gcc` or `clang` (for compiling bundled SQLite)
- SQLite development headers (included by default via bundled feature)

### Option 1: Compiling from Source

```bash
# Clone the repository
git clone https://github.com/ozdil/osint.git
cd osint

# Build optimized release binary
cargo build --release

# Inspect the binary
./target/release/osint --help
```

The resulting binary will be placed at `./target/release/osint`. You can copy it to your local path:

```bash
cp ./target/release/osint ~/.local/bin/
```

### Option 2: Running the Web Panel

```bash
# Start local interface (bound to 127.0.0.1:8787 by default)
osint serve --port 8787

# Or bind to all interfaces for reverse proxy / remote deployment:
osint serve --host 0.0.0.0 --port 8787
```

Open `http://localhost:8787` in any modern desktop or mobile browser.

---

## Production Deployment: Domain Setup (`osint.ozanozdil.com`)

To host the platform behind a custom domain like `osint.ozanozdil.com`, you can use either Cloudflare Tunnels (recommended, zero-open-ports) or Nginx/Caddy reverse proxy.

### A. Cloudflare Tunnel (Zero Trust)

1. Install `cloudflared`:
   ```bash
   curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
   sudo dpkg -i cloudflared.deb
   ```

2. Authenticate and create a tunnel:
   ```bash
   cloudflared tunnel login
   cloudflared tunnel create osint-tunnel
   ```

3. Configure `~/.cloudflared/config.yml`:
   ```yaml
   tunnel: <TUNNEL-UUID>
   credentials-file: /home/ozdil/.cloudflared/<TUNNEL-UUID>.json

   ingress:
     - hostname: osint.ozanozdil.com
       service: http://127.0.0.1:8787
     - service: http_status:404
   ```

4. Route DNS and start the tunnel service:
   ```bash
   cloudflared tunnel route dns osint-tunnel osint.ozanozdil.com
   cloudflared tunnel run osint-tunnel
   ```

### B. Nginx Reverse Proxy with Let's Encrypt SSL

```nginx
server {
    server_name osint.ozanozdil.com;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    listen 80;
}
```

Enable HTTPS via Certbot:
```bash
sudo certbot --nginx -d osint.ozanozdil.com
```

### C. Systemd Background Service

Create `/etc/systemd/system/osint.service`:

```ini
[Unit]
Description=OSINT Platform Web Service
After=network.target

[Service]
Type=simple
User=ozdil
ExecStart=/home/ozdil/.local/bin/osint serve --host 127.0.0.1 --port 8787
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Enable and activate:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now osint.service
```

---

## CLI Usage Guide

### 1. Single Target Investigations

```bash
# Domain Reconnaissance
osint domain example.com

# IP Address Triage
osint ip 93.184.216.34

# Web Technology & Tracking Footprint
osint web https://example.com

# Username Enumeration
osint user johndoe

# Email Validation & Breach Check
osint email target@example.com

# Phone Number Formatting & Intelligence
osint phone "+905551234567"

# Historic Footprint & Leak Discovery
osint history example.com
```

### 2. Deep Pivot & Force-Directed Graph Analysis

```bash
# Run 2-depth recursive pivot from a domain
osint pivot domain example.com -d 2 --max-dugum 150

# Expand out-of-scope external roots
osint pivot domain example.com -d 2 --max-dugum 200 --genis
```

### 3. Case Management & Chain of Custody Reporting

```bash
# Create an investigation case
osint vaka yeni "Target Investigation Alpha" --not "Initial intelligence phase"

# Store findings into case (ID 1)
osint --vaka 1 domain example.com
osint --vaka 1 web example.com

# Inspect all cases
osint vaka liste

# Generate reports in Markdown or Standalone HTML
osint vaka rapor 1 --bicim md > report.md
osint vaka rapor 1 --bicim html > report.html
```

---

## Configuration & Optional API Keys

API keys enhance capabilities but are not mandatory for basic operation.

```bash
# Set HaveIBeenPwned API Key (for breached email queries)
osint config set hibp_key <KEY>

# Set VirusTotal API Key (for file hash reputation)
osint config set virustotal_key <KEY>

# Set GitHub Personal Access Token (for source code queries)
osint config set github_token <TOKEN>

# Set AbuseIPDB API Key (for IP abuse reports)
osint config set abuseipdb_key <KEY>

# Inspect active configurations
osint config show
```

Configuration files are stored atomically with POSIX `0600` permissions at `~/.config/osint/config.toml`.

---

## Testing & Quality Control

Verify code health and test coverage:

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

---

## License

This project is licensed under the MIT License.
