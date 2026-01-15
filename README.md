# NetClassify

**Network Asset Classification Tool** - Automatically classify IPs and domains against your owned infrastructure for penetration testing authorization and asset management.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Features

- **Smart Classification**: Approved, SAS (SaaS/Third-Party), Review Needed, or Deny
- **Cloud Detection**: 11+ providers (AWS, Azure, GCP, Cloudflare, Akamai, etc.)
- **SaaS Detection**: 25+ services (Office 365, Salesforce, Slack, GitHub, etc.)
- **IPv6 Support**: Full IPv4/IPv6 range detection
- **Web GUI**: Modern interface with dark mode, search, and export
- **Docker Ready**: One-command deployment

## Quick Start

```bash
# Docker (recommended)
docker compose up -d
# Access at http://localhost:5001

# Or manual
pip install -r requirements.txt
python web_gui.py
```

## CSV Format

### Input CSV (Required Columns)

| Column | Description | Example |
|--------|-------------|---------|
| `value` | IP address or domain | `192.168.1.1` or `example.com` |
| `status` | Current status | `not_reviewed`, `active`, `pending` |

**Example Input:**
```csv
asset_id,value,type,source,status
1,192.168.1.1,ip_address,scan,not_reviewed
2,api.example.com,domain,discovery,not_reviewed
3,2001:db8::1,ip_address,manual,active
4,cdn.cloudflare.net,domain,scan,pending
5,10.0.0.50,ip_address,internal,not_reviewed
```

### Output CSV (Added Columns)

| Column | Description | Values |
|--------|-------------|--------|
| `new_status` | Classification result | `Approved`, `SAS`, `Review Needed`, `Deny` |
| `details` | Analysis information | DNS, Whois, provider details |

**Example Output:**
```csv
asset_id,value,type,source,status,new_status,details
1,192.168.1.1,ip_address,scan,not_reviewed,Approved,"Matches owned range 192.168.0.0/16"
2,api.example.com,domain,discovery,not_reviewed,Approved,"Subdomain of owned domain example.com"
3,2001:db8::1,ip_address,manual,active,Approved,"Matches owned IPv6 range"
4,cdn.cloudflare.net,domain,scan,pending,SAS,"Points to Cloudflare CDN"
5,10.0.0.50,ip_address,internal,not_reviewed,Deny,"No matching owned assets"
```

## Classification Results

| Status | Meaning | Action |
|--------|---------|--------|
| **Approved** | Owned by your organization | In scope for testing |
| **SAS** | Known cloud/SaaS provider | Verify authorization |
| **Review Needed** | Requires manual verification | Investigate further |
| **Deny** | External/unknown | Out of scope |

## OwnedAssets.txt Format

```
Known Public IPs
192.168.0.0/16
10.0.0.0/8
203.0.113.0/24
2001:db8::/32

Known Live Domains
example.com
*.api.example.com
corp.example.net
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scan` | POST | Start scan `{"csv_file": "file.csv", "status_filter": "all"}` |
| `/api/scan/status` | GET | Check progress |
| `/api/results` | GET | Get results |
| `/api/upload` | POST | Upload CSV (multipart) |
| `/api/download/<file>` | GET | Download results |

## Documentation

See [docs/](docs/) for detailed guides:
- [Architecture](docs/ARCHITECTURE.md)
- [API Reference](docs/API.md)
- [Configuration](docs/CONFIGURATION.md)
- [Deployment](docs/DEPLOYMENT.md)

## License

MIT License - See [LICENSE](LICENSE)

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-Support-orange.svg)](https://coff.ee/timkenobi)
