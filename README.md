# Attack Surface Mapper

A lightweight, cross-platform CLI security tool for mapping an organization's attack surface using DNSDumpster and VirusTotal APIs.

## Features

- 🔍 **DNS Enumeration**: Discover subdomains, DNS records, and network infrastructure using DNSDumpster
- 🛡️ **Threat Intelligence**: Enrich findings with VirusTotal reputation data
- 📊 **Multiple Output Formats**: JSON, CSV, and formatted table output
- 🚀 **Cross-Platform**: Works on Linux, macOS, and Windows
- ⚡ **Rate Limit Handling**: Automatic rate limit management for both APIs
- 🔐 **Secure Configuration**: Store API keys securely in a config file or environment variables

## Installation

1. Clone the repository or download the source code
2. Create a virtual environment (recommended):
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

Create a `.env` file in the project root with your API keys:

```env
DNSDUMPSTER_API_KEY=your_dnsdumpster_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```

### Getting API Keys

- **DNSDumpster**: Sign up at [dnsdumpster.com/membership](https://dnsdumpster.com/membership/) (Free tier available)
- **VirusTotal**: Get your API key at [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) (Free tier available)

## Usage

### Basic Domain Scan

```bash
python attack_surface_mapper.py scan example.com
```

### Full Scan with VirusTotal Enrichment

```bash
python attack_surface_mapper.py scan example.com --virustotal
```

### Output to JSON

```bash
python attack_surface_mapper.py scan example.com --output results.json --format json
```

### Output to CSV

```bash
python attack_surface_mapper.py scan example.com --output results.csv --format csv
```

### Verbose Output

```bash
python attack_surface_mapper.py scan example.com --verbose
```

## API Rate Limits

- **DNSDumpster**: 1 request per 2 seconds
- **VirusTotal (Free)**: 4 requests per minute, 500 per day
- **VirusTotal (Premium)**: Higher limits based on subscription

The tool automatically handles rate limiting to stay within API constraints.

## Output Information

The tool provides:

- A records (IPv4 addresses)
- NS records (nameservers)
- MX records (mail servers)
- TXT records
- CNAME records
- ASN information
- Geolocation data
- HTTP/HTTPS banner information
- VirusTotal reputation scores (when enabled)
- Malicious detections
- Community votes

## Project Structure

```
attack_surface_mapper/
├── attack_surface_mapper.py    # Main CLI entry point
├── clients/
│   ├── __init__.py
│   ├── dnsdumpster.py          # DNSDumpster API client
│   └── virustotal.py           # VirusTotal API client
├── utils/
│   ├── __init__.py
│   ├── config.py               # Configuration management
│   ├── formatter.py            # Output formatting
│   └── logger.py               # Logging utilities
├── requirements.txt
├── .env.example
└── README.md
```

## Example Output

```
Attack Surface Report for example.com
=====================================

A Records (IPv4 Addresses):
┌─────────────────┬───────────┬─────────────┬──────────────────────────┐
│ Host            │ IP        │ Country     │ ASN                      │
├─────────────────┼───────────┼─────────────┼──────────────────────────┤
│ example.com     │ 93.184... │ United St...│ 15133 - EDGECAST         │
└─────────────────┴───────────┴─────────────┴──────────────────────────┘

Nameservers:
  - a.iana-servers.net
  - b.iana-servers.net

Total records found: 15
Scan completed in 3.2 seconds
```

## Security Considerations

- Keep your API keys confidential
- Use `.env` file (not tracked in git) or environment variables
- Review rate limits to avoid account suspension
- This tool is for authorized security assessments only

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Disclaimer

This tool is intended for authorized security assessments and research purposes only. Users are responsible for complying with applicable laws and regulations. Unauthorized access to computer systems is illegal.
