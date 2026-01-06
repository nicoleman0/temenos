"""VirusTotal API client."""
import time
import requests
from typing import Dict, List, Optional


class VirusTotalClient:
    """Client for interacting with the VirusTotal API v3."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, rate_limit: float = 15.0):
        """
        Initialize VirusTotal client.

        Args:
            api_key: VirusTotal API key
            rate_limit: Minimum seconds between requests (default: 15 for 4/min)
        """
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.last_request_time = 0
        self.session = requests.Session()
        self.session.headers.update({
            'x-apikey': self.api_key,
            'User-Agent': 'AttackSurfaceMapper/1.0'
        })

    def _wait_for_rate_limit(self):
        """Ensure we respect the rate limit between requests."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time

        if time_since_last < self.rate_limit:
            sleep_time = self.rate_limit - time_since_last
            time.sleep(sleep_time)

        self.last_request_time = time.time()

    def _make_request(self, endpoint: str) -> Dict:
        """
        Make a request to the VirusTotal API.

        Args:
            endpoint: API endpoint path

        Returns:
            API response data

        Raises:
            ValueError: If request fails or returns an error
        """
        self._wait_for_rate_limit()

        url = f"{self.BASE_URL}/{endpoint}"

        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            return response.json()

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                raise ValueError(
                    "VirusTotal rate limit exceeded. Please wait before retrying.")
            elif e.response.status_code == 401:
                raise ValueError("Invalid VirusTotal API key.")
            elif e.response.status_code == 404:
                # Resource not found is not necessarily an error
                return {'data': None, 'error': 'not_found'}
            else:
                raise ValueError(
                    f"VirusTotal API error {e.response.status_code}: {e.response.text}")

        except requests.exceptions.Timeout:
            raise ValueError("VirusTotal request timed out.")

        except requests.exceptions.RequestException as e:
            raise ValueError(f"VirusTotal request failed: {str(e)}")

    def get_domain_report(self, domain: str) -> Optional[Dict]:
        """
        Get VirusTotal report for a domain.

        Args:
            domain: Domain name to check

        Returns:
            Domain report data or None if not found
        """
        try:
            result = self._make_request(f"domains/{domain}")

            if result.get('error') == 'not_found':
                return None

            return self._parse_domain_report(result)

        except ValueError as e:
            # Log error but don't fail the entire scan
            return {'error': str(e), 'domain': domain}

    def get_ip_report(self, ip: str) -> Optional[Dict]:
        """
        Get VirusTotal report for an IP address.

        Args:
            ip: IP address to check

        Returns:
            IP report data or None if not found
        """
        try:
            result = self._make_request(f"ip_addresses/{ip}")

            if result.get('error') == 'not_found':
                return None

            return self._parse_ip_report(result)

        except ValueError as e:
            # Log error but don't fail the entire scan
            return {'error': str(e), 'ip': ip}

    def _parse_domain_report(self, data: Dict) -> Dict:
        """
        Parse domain report from VirusTotal.

        Args:
            data: Raw API response

        Returns:
            Parsed domain report
        """
        if not data.get('data'):
            return {}

        attributes = data['data'].get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})

        return {
            'indicator': data['data'].get('id', ''),
            'type': 'domain',
            'stats': {
                'harmless': stats.get('harmless', 0),
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'timeout': stats.get('timeout', 0)
            },
            'reputation': attributes.get('reputation', 0),
            'total_votes': attributes.get('total_votes', {}),
            'categories': attributes.get('categories', {}),
            'last_analysis_date': attributes.get('last_analysis_date'),
        }

    def _parse_ip_report(self, data: Dict) -> Dict:
        """
        Parse IP report from VirusTotal.

        Args:
            data: Raw API response

        Returns:
            Parsed IP report
        """
        if not data.get('data'):
            return {}

        attributes = data['data'].get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})

        return {
            'indicator': data['data'].get('id', ''),
            'type': 'ip',
            'stats': {
                'harmless': stats.get('harmless', 0),
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'timeout': stats.get('timeout', 0)
            },
            'reputation': attributes.get('reputation', 0),
            'country': attributes.get('country', ''),
            'asn': attributes.get('asn', ''),
            'as_owner': attributes.get('as_owner', ''),
            'last_analysis_date': attributes.get('last_analysis_date'),
        }

    def enrich_indicators(self, domains: List[str], ips: List[str],
                          max_domains: int = 5, max_ips: int = 5) -> List[Dict]:
        """
        Enrich multiple indicators with VirusTotal data.

        Args:
            domains: List of domain names to check
            ips: List of IP addresses to check
            max_domains: Maximum number of domains to check (rate limiting)
            max_ips: Maximum number of IPs to check (rate limiting)

        Returns:
            List of enriched indicator data
        """
        results = []

        # Check domains (limited to avoid rate limits)
        for domain in domains[:max_domains]:
            report = self.get_domain_report(domain)
            if report and not report.get('error'):
                results.append(report)

        # Check IPs (limited to avoid rate limits)
        for ip in ips[:max_ips]:
            report = self.get_ip_report(ip)
            if report and not report.get('error'):
                results.append(report)

        return results
