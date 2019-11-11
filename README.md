# dnslookupfun

A repo where I store code for teaching myself about DNS. `dnspython` is a requirement for running anything within this repo.

## recordslookup.py

Script that retrieves DNS records of a domain for a given record type. Includes DMARC records.

### Usage

```
python3 recordslookup.py [-h] domain record_type

Pull DNS records for a given domain

positional arguments:
  domain
  record_type
```

Example for retrieving TXT records for example.com:

`python3 recordslookup.py example.com txt`
