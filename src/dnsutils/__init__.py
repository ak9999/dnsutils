from dnsutils._logging import configure_logging
from dnsutils.dkim import main as dkim_main
from dnsutils.dmarc import main as dmarc_main
from dnsutils.dnslookup import main
from dnsutils.spf import main as spf_main

# Configure logging when package is imported
configure_logging()

__all__ = ["main", "spf_main", "dkim_main", "dmarc_main"]
