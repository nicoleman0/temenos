"""Output formatting utilities for Attack Surface Mapper."""
import json
import csv
from datetime import datetime
from tabulate import tabulate


class OutputFormatter:
    """Handles different output formats for scan results."""

    @staticmethod
    def format_json(data, pretty=True):
        """
        Format data as JSON.

        Args:
            data: Dictionary to format
            pretty: If True, use pretty printing

        Returns:
            JSON string
        """
        if pretty:
            return json.dumps(data, indent=2, default=str)
        return json.dumps(data, default=str)

    @staticmethod
    def format_csv(data, output_file):
        """
        Format data as CSV and write to file.

        Args:
            data: Dictionary containing scan results
            output_file: Path to output file
        """
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Write A records
            if data.get('a_records'):
                writer.writerow(
                    ['Type', 'Host', 'IP', 'Country', 'ASN', 'ASN Name'])
                for record in data['a_records']:
                    for ip_info in record.get('ips', []):
                        writer.writerow([
                            'A',
                            record.get('host', ''),
                            ip_info.get('ip', ''),
                            ip_info.get('country', ''),
                            ip_info.get('asn', ''),
                            ip_info.get('asn_name', '')
                        ])
                writer.writerow([])

            # Write nameservers
            if data.get('nameservers'):
                writer.writerow(['Type', 'Nameserver', 'IP'])
                for ns in data['nameservers']:
                    for ip_info in ns.get('ips', []):
                        writer.writerow([
                            'NS',
                            ns.get('host', ''),
                            ip_info.get('ip', '')
                        ])
                writer.writerow([])

            # Write MX records
            if data.get('mx_records'):
                writer.writerow(['Type', 'Mail Server', 'IP'])
                for mx in data['mx_records']:
                    for ip_info in mx.get('ips', []):
                        writer.writerow([
                            'MX',
                            mx.get('host', ''),
                            ip_info.get('ip', '')
                        ])

    @staticmethod
    def format_table(data):
        """
        Format data as human-readable tables.

        Args:
            data: Dictionary containing scan results

        Returns:
            Formatted string with tables
        """
        output = []
        domain = data.get('domain', 'Unknown')

        # Header
        output.append(f"\n{'=' * 60}")
        output.append(f"Attack Surface Report for {domain}")
        output.append(f"{'=' * 60}\n")

        # A Records
        if data.get('a_records'):
            output.append("A Records (IPv4 Addresses):")
            a_table = []
            for record in data['a_records']:
                for ip_info in record.get('ips', []):
                    a_table.append([
                        record.get('host', '')[:30],
                        ip_info.get('ip', ''),
                        ip_info.get('country', '')[:15],
                        f"{ip_info.get('asn', '')} - {ip_info.get('asn_name', '')[:30]}"
                    ])
            output.append(tabulate(
                a_table,
                headers=['Host', 'IP Address', 'Country', 'ASN'],
                tablefmt='grid'
            ))
            output.append("")

        # Nameservers
        if data.get('nameservers'):
            output.append("Nameservers:")
            for ns in data['nameservers']:
                output.append(f"  • {ns.get('host', '')}")
                for ip_info in ns.get('ips', []):
                    output.append(
                        f"    └─ {ip_info.get('ip', '')} ({ip_info.get('country', '')})")
            output.append("")

        # MX Records
        if data.get('mx_records'):
            output.append("Mail Servers (MX Records):")
            for mx in data['mx_records']:
                output.append(f"  • {mx.get('host', '')}")
                for ip_info in mx.get('ips', []):
                    output.append(f"    └─ {ip_info.get('ip', '')}")
            output.append("")

        # TXT Records
        if data.get('txt_records'):
            output.append("TXT Records:")
            for txt in data['txt_records']:
                output.append(
                    f"  • {txt[:80]}{'...' if len(txt) > 80 else ''}")
            output.append("")

        # CNAME Records
        if data.get('cname_records'):
            output.append("CNAME Records:")
            for cname in data['cname_records']:
                output.append(
                    f"  • {cname.get('host', '')} → {cname.get('target', '')}")
            output.append("")

        # VirusTotal results
        if data.get('virustotal_results'):
            output.append("VirusTotal Threat Intelligence:")
            vt_table = []
            for vt_data in data['virustotal_results']:
                indicator = vt_data.get('indicator', '')
                stats = vt_data.get('stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)

                status = "🟢 Clean"
                if malicious > 0:
                    status = f"🔴 Malicious ({malicious})"
                elif suspicious > 0:
                    status = f"🟡 Suspicious ({suspicious})"

                vt_table.append([
                    indicator[:40],
                    status
                ])

            if vt_table:
                output.append(tabulate(
                    vt_table,
                    headers=['Indicator', 'Status'],
                    tablefmt='grid'
                ))
                output.append("")

        # Summary
        output.append("Summary:")
        output.append(f"  Total A records: {data.get('total_a_records', 0)}")
        output.append(
            f"  Scan completed: {data.get('timestamp', datetime.now().isoformat())}")
        output.append(f"\n{'=' * 60}\n")

        return "\n".join(output)
