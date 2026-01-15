# Configuration Guide

## config.yaml

### Cloud Providers
```yaml
cloud_providers:
  aws:
    name: "Amazon Web Services"
    keywords: ["amazon", "aws", "amazonaws"]
    ip_ranges: ["52.0.0.0/8", "2406:da00::/32"]
```

### Third-Party Services
```yaml
third_party_services:
  salesforce: Salesforce
  hubspot: HubSpot
  office365: Microsoft Office 365
```

### Performance
```yaml
performance:
  max_threads: 10
```

## OwnedAssets.txt

```
Known Public IPs
192.168.0.0/24
10.0.0.0/8

Known Live Domains
example.com
*.subdomain.example.com
```

**Note:** Wildcard patterns (`*.domain.com`) match all subdomains.

## Environment

| Variable | Default | Description |
|----------|---------|-------------|
| Flask Host | 0.0.0.0 | Bind address |
| Flask Port | 5001 | HTTP port |
| Debug | True | Flask debug mode |
