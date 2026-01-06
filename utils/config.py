"""Configuration management for Attack Surface Mapper."""
import os
from pathlib import Path
from dotenv import load_dotenv


class Config:
    """Configuration manager for API keys and settings."""

    def __init__(self):
        """Initialize configuration by loading from .env file or environment."""
        # Try to load from .env file in the project root
        env_path = Path(__file__).parent.parent / '.env'
        load_dotenv(env_path)

        self.dnsdumpster_api_key = os.getenv('DNSDUMPSTER_API_KEY')
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')

        # Rate limit settings
        self.dnsdumpster_rate_limit = 2  # seconds between requests
        # seconds between requests (4 per minute)
        self.virustotal_rate_limit = 15

    def validate(self, require_dnsdumpster=True, require_virustotal=False):
        """
        Validate that required API keys are present.

        Args:
            require_dnsdumpster: Whether DNSDumpster API key is required
            require_virustotal: Whether VirusTotal API key is required

        Raises:
            ValueError: If required API keys are missing
        """
        errors = []

        if require_dnsdumpster and not self.dnsdumpster_api_key:
            errors.append(
                "DNSDUMPSTER_API_KEY not found in environment or .env file")

        if require_virustotal and not self.virustotal_api_key:
            errors.append(
                "VIRUSTOTAL_API_KEY not found in environment or .env file")

        if errors:
            raise ValueError(
                "Missing required configuration:\n" +
                "\n".join(f"  - {e}" for e in errors)
            )

    def has_virustotal_key(self):
        """Check if VirusTotal API key is available."""
        return bool(self.virustotal_api_key)
