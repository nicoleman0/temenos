# Quick Start Guide - Temenos

## Setup (5 minutes)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure API Keys

Copy the example config:
```bash
cp .env.example .env
```

Edit `.env` and add your API keys:
```env
DNSDUMPSTER_API_KEY=your_actual_key_here
VIRUSTOTAL_API_KEY=your_actual_key_here
```

**Get your API keys:**
- DNSDumpster: https://dnsdumpster.com/membership/ (Free tier: 50 records)
- VirusTotal: https://www.virustotal.com/gui/my-apikey (Free tier: 4 req/min)

### 3. Verify Configuration
```bash
python temenos.py check-config
```

## Basic Usage

### Simple Domain Scan
```bash
python temenos.py scan example.com
```

### Scan with VirusTotal Threat Intelligence
```bash
python temenos.py scan example.com --virustotal
```

### Export Results to JSON
```bash
python temenos.py scan example.com -o report.json -f json
```

### Export Results to CSV
```bash
python temenos.py scan example.com -o report.csv -f csv
```

### Verbose Output for Debugging
```bash
python temenos.py scan example.com --verbose
```

## What You'll Discover

The tool maps your attack surface by finding:

✓ **All IP addresses** associated with the domain
✓ **Subdomains and hostnames** 
✓ **DNS infrastructure** (nameservers, mail servers)
✓ **Network information** (ASN, geolocation, netblocks)
✓ **Service banners** (HTTP/HTTPS server info)
✓ **Threat intelligence** (malicious indicators via VirusTotal)

## Advanced Options

### Limit VirusTotal Checks (Save API quota)
```bash
python temenos.py scan example.com --virustotal --max-vt-domains 3 --max-vt-ips 3
```

### Full Command Options
```bash
python temenos.py scan --help
```

## Typical Workflow

1. **Reconnaissance**: Start with basic scan
   ```bash
   python temenos.py scan target.com -v
   ```

2. **Threat Assessment**: Add VirusTotal enrichment
   ```bash
   python temenos.py scan target.com --virustotal
   ```

3. **Documentation**: Export results
   ```bash
   python temenos.py scan target.com --virustotal -o report.json -f json
   ```

## Troubleshooting

**"API key not found"**
- Ensure `.env` file exists in project root
- Check that API keys are set correctly
- Run `python temenos.py check-config`

**"Rate limit exceeded"****
- Wait 2 seconds between DNSDumpster requests
- Wait 15 seconds between VirusTotal requests (free tier)
- Tool handles this automatically, but manual retries need waiting

**No results found**
- Verify the domain name is correct
- Check if domain exists: `nslookup example.com`
- Try with a well-known domain first: `python temenos.py scan google.com`

## API Limits Reference

| API | Free Tier | Rate Limit |
|-----|-----------|------------|
| DNSDumpster | 50 records | 1 request / 2 seconds |
| VirusTotal | 500/day | 4 requests / minute |

## Next Steps

- Review the [README.md](README.md) for complete documentation
- Check out the code in `clients/` to understand API interactions
- Customize output formatting in `utils/formatter.py`
- Add custom analysis logic in the main script

## Legal Notice

⚠️ **Use this tool responsibly and only on domains you are authorized to assess.**

Unauthorized access to computer systems is illegal. This tool is for:
- Security assessments of your own infrastructure
- Authorized penetration testing engagements
- Security research with proper permissions
