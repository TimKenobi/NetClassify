# Architecture Overview

## System Components

```
┌─────────────────────────────────────────────────────────┐
│                    Web GUI (Flask)                       │
│                    web_gui.py:5001                       │
├─────────────────────────────────────────────────────────┤
│                 Classification Engine                    │
│                   asset_checker.py                       │
├──────────────┬──────────────┬──────────────┬────────────┤
│   DNS/Whois  │ Cloud Detect │  SaaS Detect │  IP Match  │
└──────────────┴──────────────┴──────────────┴────────────┘
```

## File Structure

| File | Purpose |
|------|---------|
| `web_gui.py` | Flask web server, REST API endpoints |
| `asset_checker.py` | Core classification logic, DNS/Whois lookups |
| `config.yaml` | Cloud providers, SaaS services, settings |
| `OwnedAssets.txt` | Organization's known IPs and domains |
| `templates/index.html` | Web interface (Bootstrap 5 + DataTables) |

## Data Flow

1. **Input**: CSV with `value` (IP/domain) and `status` columns
2. **Processing**: Multi-threaded asset analysis via ThreadPoolExecutor
3. **Classification**: IP matching → Cloud detection → SaaS detection → DNS/Whois
4. **Output**: CSV with `new_status` and `details` columns

## Classification Logic

```
Asset → Is owned IP? → Yes → Approved
         ↓ No
       Is owned domain? → Yes → Approved
         ↓ No
       Is cloud provider? → Yes → SAS
         ↓ No
       Is SaaS service? → Yes → SAS
         ↓ No
       HTTP reachable? → Yes → Review Needed
         ↓ No
       → Deny
```
