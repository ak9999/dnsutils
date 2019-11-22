# dnslookup

Retrieves DNS records for a given type. `dnspython` is a requirement for running anything within this repo.

## dnslookup.py

Script that retrieves DNS records of a domain for a given record type. Includes DMARC records.

### Usage

```
python3 dnslookup.py [-h] [--record RECORD]
                 [--nameservers NAMESERVERS [NAMESERVERS ...]]
                 domain

Pull DNS records for a given domain

positional arguments:
  domain                domain name to look up

optional arguments:
  -h, --help            show this help message and exit
  --record RECORD       record type to look up: 'A', 'MX', etc.
  --nameservers NAMESERVERS [NAMESERVERS ...]
                        nameservers used to query records
```

Example for retrieving TXT records for example.com:

`python3 dnslookup.py example.com txt`
