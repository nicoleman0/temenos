#!/usr/bin/env python3
"""
Example script demonstrating how to use Temenos programmatically.
"""
import sys
from pathlib import Path

from utils.formatter import OutputFormatter
from utils.config import Config
from clients.virustotal import VirusTotalClient
from clients.dnsdumpster import DNSDumpsterClient

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))


def main():
    """Example usage of Temenos."""

    # Load configuration
    config = Config()

    # Check if API keys are available
    try:
        config.validate(require_dnsdumpster=True, require_virustotal=False)
    except ValueError as e:
        print(f"Configuration error: {e}")
        print("\nPlease set up your .env file with API keys.")
        print("See .env.example for reference.")
        return

    # Target domain
    domain = "example.com"
    print(f"Scanning {domain}...\n")

    # Initialize DNSDumpster client
    dns_client = DNSDumpsterClient(
        api_key=config.dnsdumpster_api_key,
        rate_limit=config.dnsdumpster_rate_limit
    )

    try:
        # Get domain information
        print("[1/3] Querying DNSDumpster API...")
        raw_data = dns_client.get_domain_info(domain)
        parsed_data = dns_client.parse_results(raw_data)

        print(f"[2/3] Found {parsed_data['total_a_records']} A record(s)")

        # Extract indicators for VirusTotal
        domains = dns_client.get_all_domains(parsed_data)
        ips = dns_client.get_all_ips(parsed_data)

        print(f"      Found {len(domains)} unique domain(s)/hostname(s)")
        print(f"      Found {len(ips)} unique IP address(es)")

        # Prepare results
        results = {
            'domain': domain,
            'a_records': parsed_data['a_records'],
            'nameservers': parsed_data['nameservers'],
            'mx_records': parsed_data['mx_records'],
            'cname_records': parsed_data['cname_records'],
            'txt_records': parsed_data['txt_records'],
            'total_a_records': parsed_data['total_a_records']
        }

        # Optional: Add VirusTotal enrichment
        if config.has_virustotal_key():
            print("[3/3] Enriching with VirusTotal data...")
            vt_client = VirusTotalClient(
                api_key=config.virustotal_api_key,
                rate_limit=config.virustotal_rate_limit
            )

            # Check a few indicators (limited to save API quota)
            vt_results = vt_client.enrich_indicators(
                domains=domains[:3],  # Check first 3 domains
                ips=ips[:3],          # Check first 3 IPs
                max_domains=3,
                max_ips=3
            )

            results['virustotal_results'] = vt_results
            print(
                f"      Checked {len(vt_results)} indicator(s) with VirusTotal")
        else:
            print("[3/3] Skipping VirusTotal (no API key)")

        # Display results
        print("\n" + "="*60)
        print(OutputFormatter.format_table(results))

        # Optionally save to JSON
        # with open('example_results.json', 'w') as f:
        #     f.write(OutputFormatter.format_json(results))
        # print("Results saved to example_results.json")

    except ValueError as e:
        print(f"Error: {e}")
        return

    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        return


if __name__ == '__main__':
    main()
