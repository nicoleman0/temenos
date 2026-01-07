#!/usr/bin/env python3
"""
Temenos - CLI Security Tool
A lightweight, cross-platform security tool for mapping attack surfaces
using DNSDumpster and VirusTotal APIs.
"""
import sys
import traceback
from datetime import datetime
from pathlib import Path

import click

from utils.formatter import OutputFormatter
from utils.logger import setup_logger
from utils.config import Config
from clients.virustotal import VirusTotalClient
from clients.dnsdumpster import DNSDumpsterClient

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))


@click.group()
@click.version_option(version='1.0.0', prog_name='Temenos')
def cli():
    """
    Temenos - Map your organization's attack surface

    A lightweight CLI tool that uses DNSDumpster and VirusTotal APIs to
    discover and analyze domains, subdomains, IP addresses, and potential
    security threats.
    """


def _perform_dns_scan(domain, config, logger):
    """
    Perform DNS scan using DNSDumpster API.

    Args:
        domain: Target domain to scan
        config: Configuration object
        logger: Logger instance

    Returns:
        Dictionary with parsed DNS data
    """
    dns_client = DNSDumpsterClient(
        api_key=config.dnsdumpster_api_key,
        rate_limit=config.dnsdumpster_rate_limit
    )

    logger.info("Querying DNSDumpster API...")
    raw_data = dns_client.get_domain_info(domain)
    parsed_data = dns_client.parse_results(raw_data)

    logger.info("Found %d A record(s)", parsed_data['total_a_records'])

    return parsed_data


def _enrich_with_virustotal(parsed_data, config, logger, max_vt_domains, max_vt_ips):
    """
    Enrich results with VirusTotal data.

    Args:
        parsed_data: Parsed DNS data
        config: Configuration object
        logger: Logger instance
        max_vt_domains: Maximum domains to check
        max_vt_ips: Maximum IPs to check

    Returns:
        List of VirusTotal results
    """
    if not config.has_virustotal_key():
        logger.warning("VirusTotal API key not found. Skipping enrichment.")
        return []

    logger.info("Enriching results with VirusTotal data...")
    vt_client = VirusTotalClient(
        api_key=config.virustotal_api_key,
        rate_limit=config.virustotal_rate_limit
    )

    dns_client = DNSDumpsterClient(
        api_key=config.dnsdumpster_api_key,
        rate_limit=config.dnsdumpster_rate_limit
    )

    # Extract indicators
    domains = dns_client.get_all_domains(parsed_data)
    ips = dns_client.get_all_ips(parsed_data)

    logger.info("Checking %d domain(s) and %d IP(s) with VirusTotal...",
                min(len(domains), max_vt_domains),
                min(len(ips), max_vt_ips))

    return vt_client.enrich_indicators(
        domains=domains,
        ips=ips,
        max_domains=max_vt_domains,
        max_ips=max_vt_ips
    )


def _log_virustotal_threats(vt_results, logger):
    """
    Log threat statistics from VirusTotal results.

    Args:
        vt_results: List of VirusTotal results
        logger: Logger instance
    """
    malicious_count = sum(1 for r in vt_results
                          if r.get('stats', {}).get('malicious', 0) > 0)
    suspicious_count = sum(1 for r in vt_results
                           if r.get('stats', {}).get('suspicious', 0) > 0)

    if malicious_count > 0:
        logger.warning(
            "⚠️  Found %d indicator(s) flagged as malicious", malicious_count)
    if suspicious_count > 0:
        logger.warning(
            "⚠️  Found %d indicator(s) flagged as suspicious", suspicious_count)

    if malicious_count == 0 and suspicious_count == 0:
        logger.info("✓ No threats detected by VirusTotal")


def _write_output(formatted_output, output_path, logger):
    """
    Write formatted output to file or stdout.

    Args:
        formatted_output: Formatted string output
        output_path: Path to output file (None for stdout)
        logger: Logger instance
    """
    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(formatted_output)
        logger.info("Results saved to: %s", output_path)
    else:
        click.echo(formatted_output)


def _handle_output_format(results, output_format, output, logger):
    """
    Handle output formatting based on user choice.

    Args:
        results: Scan results dictionary
        output_format: Output format type
        output: Output file path (optional)
        logger: Logger instance
    """
    if output_format == 'json':
        formatted_output = OutputFormatter.format_json(results)
        _write_output(formatted_output, output, logger)

    elif output_format == 'csv':
        if not output:
            logger.error("CSV format requires --output option")
            sys.exit(1)
        OutputFormatter.format_csv(results, output)
        logger.info("Results saved to: %s", output)

    elif output_format == 'html':
        formatted_output = OutputFormatter.format_html(results)
        _write_output(formatted_output, output, logger)

    elif output_format == 'xml':
        formatted_output = OutputFormatter.format_xml(results)
        _write_output(formatted_output, output, logger)

    elif output_format == 'markdown':
        formatted_output = OutputFormatter.format_markdown(results)
        _write_output(formatted_output, output, logger)

    else:  # table format
        formatted_output = OutputFormatter.format_table(results)
        _write_output(formatted_output, output, logger)


@cli.command()
@click.argument('domain')
@click.option('--virustotal', '-vt', is_flag=True,
              help='Enable VirusTotal enrichment (requires API key)')
@click.option('--output', '-o', type=click.Path(),
              help='Output file path (optional)')
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['json', 'csv', 'table', 'html', 'xml', 'markdown'],
                                case_sensitive=False),
              default='table',
              help='Output format (default: table)')
@click.option('--verbose', '-v', is_flag=True,
              help='Enable verbose output')
@click.option('--max-vt-domains', type=int, default=5,
              help='Maximum domains to check with VirusTotal (default: 5)')
@click.option('--max-vt-ips', type=int, default=5,
              help='Maximum IPs to check with VirusTotal (default: 5)')
def scan(domain, virustotal, output, output_format, verbose, max_vt_domains, max_vt_ips):
    """
    Scan a domain to discover its attack surface.

    DOMAIN: The target domain to scan (e.g., example.com)

    Examples:

      \b
      # Basic scan with table output
      python temenos.py scan example.com

      \b
      # Scan with VirusTotal enrichment
      python temenos.py scan example.com --virustotal

      \b
      # Export to JSON
      python temenos.py scan example.com -o results.json -f json

      \b
      # Export to CSV
      python temenos.py scan example.com -o results.csv -f csv

      \b
      # Export to HTML
      python temenos.py scan example.com -o report.html -f html

      \b
      # Export to XML
      python temenos.py scan example.com -o results.xml -f xml

      \b
      # Export to Markdown
      python temenos.py scan example.com -o report.md -f markdown
    """
    logger = setup_logger(verbose=verbose)

    try:
        # Load configuration
        config = Config()
        config.validate(require_dnsdumpster=True,
                        require_virustotal=virustotal)

        logger.info("Starting Temeneos scan for: %s", domain)

        # Perform DNSDumpster scan
        parsed_data = _perform_dns_scan(domain, config, logger)

        # Prepare results
        results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'a_records': parsed_data['a_records'],
            'nameservers': parsed_data['nameservers'],
            'mx_records': parsed_data['mx_records'],
            'cname_records': parsed_data['cname_records'],
            'txt_records': parsed_data['txt_records'],
            'total_a_records': parsed_data['total_a_records']
        }

        # VirusTotal enrichment if enabled
        if virustotal:
            vt_results = _enrich_with_virustotal(
                parsed_data, config, logger, max_vt_domains, max_vt_ips
            )
            results['virustotal_results'] = vt_results
            _log_virustotal_threats(vt_results, logger)

        # Format and output results
        _handle_output_format(results, output_format, output, logger)

        logger.info("Scan completed successfully!")

    except ValueError as e:
        logger.error("Error: %s", e)
        sys.exit(1)

    except KeyboardInterrupt:
        logger.warning("\nScan interrupted by user")
        sys.exit(130)

    except Exception as e:
        logger.error("Unexpected error: %s", e)
        if verbose:
            traceback.print_exc()
        sys.exit(1)


@cli.command()
def check_config():
    """
    Check configuration and API key status.

    Validates that API keys are properly configured and accessible.
    """
    click.echo("Checking configuration...\n")

    config = Config()

    # Check DNSDumpster
    if config.dnsdumpster_api_key:
        click.echo("✓ DNSDumpster API key: Found")
    else:
        click.echo("✗ DNSDumpster API key: Not found")
        click.echo("  Set DNSDUMPSTER_API_KEY in .env file or environment")

    # Check VirusTotal
    if config.virustotal_api_key:
        click.echo("✓ VirusTotal API key: Found")
    else:
        click.echo("✗ VirusTotal API key: Not found (optional)")
        click.echo("  Set VIRUSTOTAL_API_KEY in .env file or environment")

    click.echo("\nConfiguration file: .env")
    click.echo("Example configuration file: .env.example")

    if not config.dnsdumpster_api_key:
        click.echo("\n⚠️  DNSDumpster API key is required for scanning")
        click.echo("Get your API key at: https://dnsdumpster.com/membership/")
        sys.exit(1)
    else:
        click.echo("\n✓ Configuration is valid!")


if __name__ == '__main__':
    cli()
