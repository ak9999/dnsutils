# dnsutils

A suite of DNS utilities for retrieving DNS records and analyzing email authentication configurations.

## Features

- **dnslookup** — Query DNS records for any domain and record type
- **spf** — Check and analyze SPF (Sender Policy Framework) records
- **dkim** — Validate DKIM (DomainKeys Identified Mail) records
- **dmarc** — Analyze DMARC (Domain-based Message Authentication, Reporting & Conformance) policies

## Requirements

- **Python:** 3.13 or higher
- **Dependencies:** dnspython >= 2.6.1

## Installation

### Using `uv` (Recommended)

```bash
git clone <repository-url>
cd dnsutils
uv sync
```

### Using pip

```bash
git clone <repository-url>
cd dnsutils
pip install -e .
```

## Usage

### dnslookup - Generic DNS Lookup

Query any DNS record type for a domain:

```bash
# Look up A records (default)
dnsutils example.com

# Look up specific record types
dnsutils example.com --record MX
dnsutils example.com --record TXT
dnsutils example.com --record AAAA
dnsutils example.com --record CNAME

# Special DMARC pseudo-type
dnsutils example.com --record dmarc

# Use custom nameservers
dnsutils example.com --nameservers 8.8.8.8 1.1.1.1
```

### spf - SPF Record Checker

Retrieve and analyze SPF (Sender Policy Framework) records:

```bash
# Check SPF record
spf example.com

# Use custom nameservers
spf example.com --nameservers 8.8.8.8 1.1.1.1
```

**Output includes:**
- Full SPF record
- Parsed mechanisms (ip4, ip6, a, mx, include, etc.)
- Modifiers (exp, redirect, etc.)

### dkim - DKIM Record Validator

Retrieve and validate DKIM (DomainKeys Identified Mail) records:

```bash
# Check DKIM record with a specific selector
dkim example.com default

# Use different selectors
dkim example.com google
dkim example.com selector1

# Use custom nameservers
dkim example.com default --nameservers 8.8.8.8 1.1.1.1
```

**Output includes:**
- DKIM record content
- Version (v=DKIM1)
- Key type (RSA, etc.)
- Hash algorithm (SHA256, etc.)
- Public key (truncated for display)

### dmarc - DMARC Policy Analyzer

Retrieve and analyze DMARC (Domain-based Message Authentication, Reporting & Conformance) policies:

```bash
# Check DMARC policy
dmarc example.com

# Use custom nameservers
dmarc example.com --nameservers 8.8.8.8 1.1.1.1
```

**Output includes:**
- Full DMARC record
- Version (v=DMARC1)
- Policy strength assessment (reject, quarantine, none)
- Alignment modes (DKIM and SPF)
- Reporting URIs (aggregate and forensic)
- Percentage settings

## Development

### Running Tests

Run the full test suite with coverage:

```bash
uv run pytest tests/ --cov=src/dnsutils
```

Run specific test file:

```bash
uv run pytest tests/test_spf.py -v
```

### Type Checking

Check for type errors using `ty`:

```bash
uv run ty check
```

### Code Formatting

Format code with ruff:

```bash
uv run ruff format src/dnsutils tests/
```

### Installing Development Dependencies

```bash
uv sync
```

This installs all development tools: pytest, pytest-cov, ruff, and ty.

## Project Structure

```
dnsutils/
├── src/dnsutils/
│   ├── __init__.py           # Package initialization
│   ├── _logging.py           # Logging configuration
│   ├── _dns_utils.py         # Shared DNS utilities
│   ├── exceptions.py         # Custom exception classes
│   ├── dnslookup.py          # Generic DNS lookup
│   ├── spf.py                # SPF checker
│   ├── dkim.py               # DKIM validator
│   └── dmarc.py              # DMARC analyzer
├── tests/
│   ├── test_dnslookup.py
│   ├── test_spf.py
│   ├── test_dkim.py
│   └── test_dmarc.py
├── pyproject.toml            # Project metadata and dependencies
└── README.md                 # This file
```

## Error Handling

All tools provide clear error messages when:
- Domain not found (NXDOMAIN)
- No records exist for the domain
- Invalid record types specified
- No nameservers available
- DNS queries timeout

Exit code 1 indicates a DNS lookup error; exit code 0 indicates success.

## Examples

### Check email authentication for gmail.com

```bash
# SPF policy
spf gmail.com

# DKIM (with Google's selector)
dkim gmail.com google

# DMARC policy
dmarc gmail.com
```

### Audit a domain's DNS configuration

```bash
# Check all important records
dnsutils example.com --record A
dnsutils example.com --record MX
dnsutils example.com --record TXT

# Email authentication
spf example.com
dkim example.com default
dmarc example.com
```

## License

MIT License

## Contributing

See CLAUDE.md for development guidelines.
