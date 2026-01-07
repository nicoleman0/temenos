"""Output formatting utilities for Temenos."""
import json
import csv
import html
from datetime import datetime
from tabulate import tabulate
from jinja2 import Template


# Constants
TOOL_VERSION = "1.0.0"
TXT_RECORD_MAX_LENGTH = 100

# HTML Template (compiled once for efficiency)
HTML_TEMPLATE = Template("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Temenos Security Report - {{ domain }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        h2 {
            color: #34495e;
            margin-top: 30px;
            margin-bottom: 15px;
            padding-left: 10px;
            border-left: 4px solid #3498db;
        }
        .meta {
            background: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .meta p { margin: 5px 0; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            background: white;
        }
        th {
            background: #34495e;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        td {
            padding: 10px 12px;
            border-bottom: 1px solid #ecf0f1;
        }
        tr:hover { background: #f8f9fa; }
        .status-clean { color: #27ae60; font-weight: bold; }
        .status-suspicious { color: #f39c12; font-weight: bold; }
        .status-malicious { color: #e74c3c; font-weight: bold; }
        .section {
            margin: 20px 0;
            padding: 20px;
            background: #fafafa;
            border-radius: 5px;
        }
        .record-item {
            margin: 10px 0;
            padding: 10px;
            background: white;
            border-left: 3px solid #3498db;
        }
        .record-item ul {
            list-style: none;
            margin-left: 20px;
            margin-top: 5px;
        }
        .record-item li {
            padding: 3px 0;
            color: #7f8c8d;
        }
        .summary {
            background: #e8f4f8;
            padding: 20px;
            border-radius: 5px;
            margin-top: 30px;
            border-left: 4px solid #3498db;
        }
        .txt-record {
            font-family: 'Courier New', monospace;
            background: #f8f9fa;
            padding: 8px;
            border-radius: 3px;
            word-break: break-all;
            margin: 5px 0;
        }
        @media print {
            body { background: white; }
            .container { box-shadow: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Temenos Security Report</h1>
        
        <div class="meta">
            <p><strong>Domain:</strong> {{ domain }}</p>
            <p><strong>Scan Date:</strong> {{ timestamp }}</p>
            <p><strong>Total A Records:</strong> {{ total_a_records }}</p>
        </div>

        {% if a_records %}
        <h2>A Records (IPv4 Addresses)</h2>
        <table>
            <thead>
                <tr>
                    <th>Host</th>
                    <th>IP Address</th>
                    <th>Country</th>
                    <th>ASN</th>
                    <th>ASN Name</th>
                </tr>
            </thead>
            <tbody>
                {% for record in a_records %}
                    {% for ip_info in record.ips %}
                    <tr>
                        <td>{{ record.host }}</td>
                        <td>{{ ip_info.ip }}</td>
                        <td>{{ ip_info.country }}</td>
                        <td>{{ ip_info.asn }}</td>
                        <td>{{ ip_info.asn_name }}</td>
                    </tr>
                    {% endfor %}
                {% endfor %}
            </tbody>
        </table>
        {% endif %}

        {% if nameservers %}
        <h2>Nameservers</h2>
        <div class="section">
            {% for ns in nameservers %}
            <div class="record-item">
                <strong>{{ ns.host }}</strong>
                <ul>
                    {% for ip_info in ns.ips %}
                    <li>└─ {{ ip_info.ip }} ({{ ip_info.country }})</li>
                    {% endfor %}
                </ul>
            </div>
            {% endfor %}
        </div>
        {% endif %}

        {% if mx_records %}
        <h2>Mail Servers (MX Records)</h2>
        <div class="section">
            {% for mx in mx_records %}
            <div class="record-item">
                <strong>{{ mx.host }}</strong>
                <ul>
                    {% for ip_info in mx.ips %}
                    <li>└─ {{ ip_info.ip }}</li>
                    {% endfor %}
                </ul>
            </div>
            {% endfor %}
        </div>
        {% endif %}

        {% if cname_records %}
        <h2>CNAME Records</h2>
        <div class="section">
            {% for cname in cname_records %}
            <div class="record-item">
                {{ cname.host }} → {{ cname.target }}
            </div>
            {% endfor %}
        </div>
        {% endif %}

        {% if txt_records %}
        <h2>TXT Records</h2>
        <div class="section">
            {% for txt in txt_records %}
            <div class="txt-record">{{ txt }}</div>
            {% endfor %}
        </div>
        {% endif %}

        {% if virustotal_results %}
        <h2>VirusTotal Threat Intelligence</h2>
        <table>
            <thead>
                <tr>
                    <th>Indicator</th>
                    <th>Type</th>
                    <th>Status</th>
                    <th>Malicious</th>
                    <th>Suspicious</th>
                </tr>
            </thead>
            <tbody>
                {% for vt in virustotal_results %}
                <tr>
                    <td>{{ vt.indicator }}</td>
                    <td>{{ vt.type }}</td>
                    <td>
                        {% if vt.stats.malicious > 0 %}
                        <span class="status-malicious">🔴 Malicious</span>
                        {% elif vt.stats.suspicious > 0 %}
                        <span class="status-suspicious">🟡 Suspicious</span>
                        {% else %}
                        <span class="status-clean">🟢 Clean</span>
                        {% endif %}
                    </td>
                    <td>{{ vt.stats.malicious }}</td>
                    <td>{{ vt.stats.suspicious }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}

        <div class="summary">
            <h2>Summary</h2>
            <p><strong>Total A Records:</strong> {{ total_a_records }}</p>
            <p><strong>Nameservers:</strong> {{ nameservers|length }}</p>
            <p><strong>MX Records:</strong> {{ mx_records|length }}</p>
            <p><strong>CNAME Records:</strong> {{ cname_records|length }}</p>
            <p><strong>TXT Records:</strong> {{ txt_records|length }}</p>
            {% if virustotal_results %}
            <p><strong>VirusTotal Checks:</strong> {{ virustotal_results|length }}</p>
            {% endif %}
        </div>
    </div>
</body>
</html>""")


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

    @staticmethod
    def format_html(data):
        """
        Format data as HTML report.

        Args:
            data: Dictionary containing scan results

        Returns:
            HTML string with embedded CSS
        """
        return HTML_TEMPLATE.render(
            domain=data.get('domain', 'Unknown'),
            timestamp=data.get('timestamp', datetime.now().isoformat()),
            total_a_records=data.get('total_a_records', 0),
            a_records=data.get('a_records', []),
            nameservers=data.get('nameservers', []),
            mx_records=data.get('mx_records', []),
            cname_records=data.get('cname_records', []),
            txt_records=data.get('txt_records', []),
            virustotal_results=data.get('virustotal_results', [])
        )

    @staticmethod
    def _escape_xml(text):
        """Escape special XML characters."""
        if text is None:
            return ''
        return html.escape(str(text))

    @staticmethod
    def _format_xml_a_records(data, escape_func):
        """Format A records section for XML."""
        lines = []
        if data.get('a_records'):
            lines.append('    <a_records>')
            for record in data['a_records']:
                lines.append('      <a_record>')
                host_value = escape_func(record.get("host", ""))
                lines.append(f'        <host>{host_value}</host>')
                if record.get('ips'):
                    lines.append('        <ip_addresses>')
                    for ip_info in record['ips']:
                        lines.append('          <ip_address>')
                        ip_val = escape_func(ip_info.get("ip", ""))
                        lines.append(f'            <ip>{ip_val}</ip>')
                        country_val = escape_func(ip_info.get("country", ""))
                        lines.append(
                            f'            <country>{country_val}</country>')
                        asn_val = escape_func(ip_info.get("asn", ""))
                        lines.append(f'            <asn>{asn_val}</asn>')
                        asn_name_val = escape_func(ip_info.get("asn_name", ""))
                        lines.append(
                            f'            <asn_name>{asn_name_val}</asn_name>')
                        lines.append('          </ip_address>')
                    lines.append('        </ip_addresses>')
                lines.append('      </a_record>')
            lines.append('    </a_records>')
        return lines

    @staticmethod
    def _format_xml_nameservers(data, escape_func):
        """Format nameservers section for XML."""
        lines = []
        if data.get('nameservers'):
            lines.append('    <nameservers>')
            for ns in data['nameservers']:
                lines.append('      <nameserver>')
                host_val = escape_func(ns.get("host", ""))
                lines.append(f'        <host>{host_val}</host>')
                if ns.get('ips'):
                    lines.append('        <ip_addresses>')
                    for ip_info in ns['ips']:
                        lines.append('          <ip_address>')
                        ip_val = escape_func(ip_info.get("ip", ""))
                        lines.append(f'            <ip>{ip_val}</ip>')
                        country_val = escape_func(ip_info.get("country", ""))
                        lines.append(
                            f'            <country>{country_val}</country>')
                        lines.append('          </ip_address>')
                    lines.append('        </ip_addresses>')
                lines.append('      </nameserver>')
            lines.append('    </nameservers>')
        return lines

    @staticmethod
    def _format_xml_mx_records(data, escape_func):
        """Format MX records section for XML."""
        lines = []
        if data.get('mx_records'):
            lines.append('    <mx_records>')
            for mx in data['mx_records']:
                lines.append('      <mx_record>')
                host_val = escape_func(mx.get("host", ""))
                lines.append(f'        <host>{host_val}</host>')
                if mx.get('ips'):
                    lines.append('        <ip_addresses>')
                    for ip_info in mx['ips']:
                        lines.append('          <ip_address>')
                        ip_val = escape_func(ip_info.get("ip", ""))
                        lines.append(f'            <ip>{ip_val}</ip>')
                        lines.append('          </ip_address>')
                    lines.append('        </ip_addresses>')
                lines.append('      </mx_record>')
            lines.append('    </mx_records>')
        return lines

    @staticmethod
    def _format_xml_cname_txt_records(data, escape_func):
        """Format CNAME and TXT records sections for XML."""
        lines = []
        # CNAME Records
        if data.get('cname_records'):
            lines.append('    <cname_records>')
            for cname in data['cname_records']:
                lines.append('      <cname_record>')
                host_val = escape_func(cname.get("host", ""))
                lines.append(f'        <host>{host_val}</host>')
                target_val = escape_func(cname.get("target", ""))
                lines.append(f'        <target>{target_val}</target>')
                lines.append('      </cname_record>')
            lines.append('    </cname_records>')

        # TXT Records
        if data.get('txt_records'):
            lines.append('    <txt_records>')
            for txt in data['txt_records']:
                txt_val = escape_func(txt)
                lines.append(f'      <txt_record>{txt_val}</txt_record>')
            lines.append('    </txt_records>')
        return lines

    @staticmethod
    def _format_xml_virustotal_results(data, escape_func):
        """Format VirusTotal results section for XML."""
        lines = []
        if data.get('virustotal_results'):
            lines.append('  <virustotal_results>')
            for vt in data['virustotal_results']:
                lines.append('    <result>')
                indicator_val = escape_func(vt.get("indicator", ""))
                lines.append(f'      <indicator>{indicator_val}</indicator>')
                type_val = escape_func(vt.get("type", ""))
                lines.append(f'      <type>{type_val}</type>')
                if vt.get('stats'):
                    stats = vt['stats']
                    lines.append('      <statistics>')
                    mal_count = stats.get("malicious", 0)
                    lines.append(f'        <malicious>{mal_count}</malicious>')
                    sus_count = stats.get("suspicious", 0)
                    lines.append(
                        f'        <suspicious>{sus_count}</suspicious>')
                    harm_count = stats.get("harmless", 0)
                    lines.append(f'        <harmless>{harm_count}</harmless>')
                    undet_count = stats.get("undetected", 0)
                    lines.append(
                        f'        <undetected>{undet_count}</undetected>')
                    lines.append('      </statistics>')
                lines.append('    </result>')
            lines.append('  </virustotal_results>')
        return lines

    @staticmethod
    def format_xml(data):
        """
        Format data as XML.

        Args:
            data: Dictionary containing scan results

        Returns:
            XML string with proper schema
        """
        escape_func = OutputFormatter._escape_xml

        lines = ['<?xml version="1.0" encoding="UTF-8"?>']
        lines.append('<temenos_scan>')
        lines.append('  <metadata>')
        domain_value = escape_func(data.get("domain", "Unknown"))
        lines.append(f'    <domain>{domain_value}</domain>')
        timestamp_value = escape_func(
            data.get("timestamp", datetime.now().isoformat())
        )
        lines.append(f'    <timestamp>{timestamp_value}</timestamp>')
        lines.append(f'    <tool_version>{TOOL_VERSION}</tool_version>')
        lines.append('  </metadata>')

        # A Records
        if data.get('a_records'):
            lines.append('  <dns_records>')
            lines.extend(
                OutputFormatter._format_xml_a_records(data, escape_func))
            lines.extend(
                OutputFormatter._format_xml_nameservers(data, escape_func))
            lines.extend(
                OutputFormatter._format_xml_mx_records(data, escape_func))
            lines.extend(
                OutputFormatter._format_xml_cname_txt_records(data, escape_func))
            lines.append('  </dns_records>')

        # VirusTotal Results
        lines.extend(
            OutputFormatter._format_xml_virustotal_results(data, escape_func))

        # Summary
        lines.append('  <summary>')
        total_a = data.get("total_a_records", 0)
        lines.append(f'    <total_a_records>{total_a}</total_a_records>')
        total_ns = len(data.get("nameservers", []))
        lines.append(f'    <total_nameservers>{total_ns}</total_nameservers>')
        total_mx = len(data.get("mx_records", []))
        lines.append(f'    <total_mx_records>{total_mx}</total_mx_records>')
        total_cname = len(data.get("cname_records", []))
        lines.append(
            f'    <total_cname_records>{total_cname}</total_cname_records>')
        total_txt = len(data.get("txt_records", []))
        lines.append(f'    <total_txt_records>{total_txt}</total_txt_records>')
        lines.append('  </summary>')

        lines.append('</temenos_scan>')
        return '\n'.join(lines)

    @staticmethod
    def _format_markdown_header(data):
        """Format header section for Markdown."""
        lines = []
        domain = data.get('domain', 'Unknown')
        timestamp = data.get('timestamp', datetime.now().isoformat())

        lines.append("# 🛡️ Temenos Security Report")
        lines.append("")
        lines.append(f"**Domain:** `{domain}`  ")
        lines.append(f"**Scan Date:** {timestamp}  ")
        lines.append(f"**Total A Records:** {data.get('total_a_records', 0)}")
        lines.append("")
        lines.append("---")
        lines.append("")
        return lines

    @staticmethod
    def _format_markdown_a_records(data):
        """Format A records section for Markdown."""
        lines = []
        if data.get('a_records'):
            lines.append("## 📍 A Records (IPv4 Addresses)")
            lines.append("")
            lines.append("| Host | IP Address | Country | ASN | ASN Name |")
            lines.append("|------|-----------|---------|-----|----------|")
            for record in data['a_records']:
                for ip_info in record.get('ips', []):
                    host = record.get('host', '')
                    ip = ip_info.get('ip', '')
                    country = ip_info.get('country', '')
                    asn = ip_info.get('asn', '')
                    asn_name = ip_info.get('asn_name', '')
                    line = f"| `{host}` | `{ip}` | {country} | {asn} | {asn_name} |"
                    lines.append(line)
            lines.append("")
        return lines

    @staticmethod
    def _format_markdown_nameservers_mx(data):
        """Format nameservers and MX records sections for Markdown."""
        lines = []
        # Nameservers
        if data.get('nameservers'):
            lines.append("## 🌐 Nameservers")
            lines.append("")
            for ns in data['nameservers']:
                lines.append(f"- **{ns.get('host', '')}**")
                for ip_info in ns.get('ips', []):
                    ip_addr = ip_info.get('ip', '')
                    country = ip_info.get('country', '')
                    lines.append(f"  - `{ip_addr}` ({country})")
            lines.append("")

        # MX Records
        if data.get('mx_records'):
            lines.append("## 📧 Mail Servers (MX Records)")
            lines.append("")
            for mx in data['mx_records']:
                lines.append(f"- **{mx.get('host', '')}**")
                for ip_info in mx.get('ips', []):
                    lines.append(f"  - `{ip_info.get('ip', '')}`")
            lines.append("")
        return lines

    @staticmethod
    def _format_markdown_cname_txt(data):
        """Format CNAME and TXT records sections for Markdown."""
        lines = []
        # CNAME Records
        if data.get('cname_records'):
            lines.append("## 🔗 CNAME Records")
            lines.append("")
            for cname in data['cname_records']:
                host = cname.get('host', '')
                target = cname.get('target', '')
                lines.append(f"- `{host}` → `{target}`")
            lines.append("")

        # TXT Records
        if data.get('txt_records'):
            lines.append("## 📝 TXT Records")
            lines.append("")
            for txt in data['txt_records']:
                # Truncate long TXT records for readability
                if len(txt) > TXT_RECORD_MAX_LENGTH:
                    lines.append(f"- `{txt[:TXT_RECORD_MAX_LENGTH]}...`")
                else:
                    lines.append(f"- `{txt}`")
            lines.append("")
        return lines

    @staticmethod
    def _format_markdown_virustotal(data):
        """Format VirusTotal results section for Markdown."""
        lines = []
        if data.get('virustotal_results'):
            lines.append("## 🔍 VirusTotal Threat Intelligence")
            lines.append("")
            lines.append(
                "| Indicator | Type | Status | Malicious | Suspicious |")
            lines.append(
                "|-----------|------|--------|-----------|------------|")
            for vt in data['virustotal_results']:
                indicator = vt.get('indicator', '')
                vt_type = vt.get('type', '')
                stats = vt.get('stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)

                if malicious > 0:
                    status = f"🔴 **Malicious** ({malicious})"
                elif suspicious > 0:
                    status = f"🟡 **Suspicious** ({suspicious})"
                else:
                    status = "🟢 Clean"

                line = f"| `{indicator}` | {vt_type} | {status} | {malicious} | {suspicious} |"
                lines.append(line)
            lines.append("")
        return lines

    @staticmethod
    def _format_markdown_summary(data):
        """Format summary section for Markdown."""
        lines = []
        lines.append("---")
        lines.append("")
        lines.append("## 📊 Summary")
        lines.append("")
        lines.append(
            f"- **Total A Records:** {data.get('total_a_records', 0)}")
        lines.append(f"- **Nameservers:** {len(data.get('nameservers', []))}")
        lines.append(f"- **MX Records:** {len(data.get('mx_records', []))}")
        lines.append(
            f"- **CNAME Records:** {len(data.get('cname_records', []))}")
        lines.append(f"- **TXT Records:** {len(data.get('txt_records', []))}")

        if data.get('virustotal_results'):
            vt_count = len(data['virustotal_results'])
            lines.append(f"- **VirusTotal Checks:** {vt_count}")

            # Count threats
            vt_results = data['virustotal_results']
            malicious_count = sum(
                1 for r in vt_results
                if r.get('stats', {}).get('malicious', 0) > 0
            )
            suspicious_count = sum(
                1 for r in vt_results
                if r.get('stats', {}).get('suspicious', 0) > 0
            )

            if malicious_count > 0:
                lines.append(
                    f"- **⚠️ Malicious Indicators:** {malicious_count}")
            if suspicious_count > 0:
                lines.append(
                    f"- **⚠️ Suspicious Indicators:** {suspicious_count}")

        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("*Generated by Temenos Security Scanner*")
        lines.append("")
        return lines

    @staticmethod
    def format_markdown(data):
        """
        Format data as Markdown document.

        Args:
            data: Dictionary containing scan results

        Returns:
            Markdown string compatible with GitHub/GitLab
        """
        lines = []

        # Build sections using helper methods
        lines.extend(OutputFormatter._format_markdown_header(data))
        lines.extend(OutputFormatter._format_markdown_a_records(data))
        lines.extend(OutputFormatter._format_markdown_nameservers_mx(data))
        lines.extend(OutputFormatter._format_markdown_cname_txt(data))
        lines.extend(OutputFormatter._format_markdown_virustotal(data))
        lines.extend(OutputFormatter._format_markdown_summary(data))

        return '\n'.join(lines)
