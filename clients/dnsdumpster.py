"""DNSDumpster API client."""
import time
import requests
from typing import Dict, Optional


class DNSDumpsterClient:
    """Client for interacting with the DNSDumpster API."""

    BASE_URL = "https://api.dnsdumpster.com"

    def __init__(self, api_key: str, rate_limit: float = 2.0):
        """
        Initialize DNSDumpster client.

        Args:
            api_key: DNSDumpster API key
            rate_limit: Minimum seconds between requests (default: 2.0)
        """
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.last_request_time = 0
        self.session = requests.Session()
        self.session.headers.update({
            'X-API-Key': self.api_key,
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

    def get_domain_info(self, domain: str, page: int = 1, include_map: bool = False) -> Dict:
        """
        Get comprehensive DNS and attack surface information for a domain.

        Args:
            domain: Domain name to scan
            page: Page number for pagination (requires Plus membership)
            include_map: Include domain map in response (requires Plus membership)

        Returns:
            Dictionary containing DNS records and attack surface data

        Raises:
            requests.HTTPError: If the API request fails
            ValueError: If response is invalid
        """
        self._wait_for_rate_limit()

        url = f"{self.BASE_URL}/domain/{domain}"
        params = {}

        if page > 1:
            params['page'] = page

        if include_map:
            params['map'] = 1

        try:
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()

            data = response.json()

            # Check for error in response
            if 'error' in data:
                raise ValueError(f"API Error: {data['error']}")

            return data

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                raise ValueError(
                    "Rate limit exceeded. Please wait before making another request.")
            elif e.response.status_code == 401:
                raise ValueError(
                    "Invalid API key. Please check your DNSDumpster API key.")
            elif e.response.status_code == 403:
                raise ValueError(
                    "Access forbidden. Check your API key and membership level.")
            else:
                raise ValueError(
                    f"HTTP Error {e.response.status_code}: {e.response.text}")

        except requests.exceptions.Timeout:
            raise ValueError("Request timed out. Please try again.")

        except requests.exceptions.RequestException as e:
            raise ValueError(f"Request failed: {str(e)}")

        except ValueError as e:
            if "JSON" in str(e):
                raise ValueError("Invalid JSON response from API")
            raise

    def parse_results(self, data: Dict) -> Dict:
        """
        Parse DNSDumpster results into a standardized format.

        Args:
            data: Raw API response data

        Returns:
            Parsed and structured data
        """
        parsed = {
            'a_records': [],
            'nameservers': [],
            'mx_records': [],
            'cname_records': [],
            'txt_records': [],
            'total_a_records': data.get('total_a_recs', 0)
        }

        # Parse A records
        if data.get('a'):
            parsed['a_records'] = data['a']

        # Parse nameservers
        if data.get('ns'):
            parsed['nameservers'] = data['ns']

        # Parse MX records
        if data.get('mx'):
            parsed['mx_records'] = data['mx']

        # Parse CNAME records
        if data.get('cname'):
            parsed['cname_records'] = data['cname']

        # Parse TXT records
        if data.get('txt'):
            parsed['txt_records'] = data['txt']

        return parsed

    def get_all_ips(self, parsed_data: Dict) -> list:
        """
        Extract all unique IP addresses from parsed data.

        Args:
            parsed_data: Parsed DNSDumpster data

        Returns:
            List of unique IP addresses
        """
        ips = set()

        # Extract from A records
        for record in parsed_data.get('a_records', []):
            for ip_info in record.get('ips', []):
                if ip_info.get('ip'):
                    ips.add(ip_info['ip'])

        # Extract from nameservers
        for ns in parsed_data.get('nameservers', []):
            for ip_info in ns.get('ips', []):
                if ip_info.get('ip'):
                    ips.add(ip_info['ip'])

        # Extract from MX records
        for mx in parsed_data.get('mx_records', []):
            for ip_info in mx.get('ips', []):
                if ip_info.get('ip'):
                    ips.add(ip_info['ip'])

        return list(ips)

    def get_all_domains(self, parsed_data: Dict) -> list:
        """
        Extract all unique domain/hostname from parsed data.

        Args:
            parsed_data: Parsed DNSDumpster data

        Returns:
            List of unique domains/hostnames
        """
        domains = set()

        # Extract from A records
        for record in parsed_data.get('a_records', []):
            if record.get('host'):
                domains.add(record['host'])

        # Extract from nameservers
        for ns in parsed_data.get('nameservers', []):
            if ns.get('host'):
                domains.add(ns['host'])

        # Extract from MX records
        for mx in parsed_data.get('mx_records', []):
            if mx.get('host'):
                domains.add(mx['host'])

        # Extract from CNAME records
        for cname in parsed_data.get('cname_records', []):
            if cname.get('host'):
                domains.add(cname['host'])
            if cname.get('target'):
                domains.add(cname['target'])

        return list(domains)
