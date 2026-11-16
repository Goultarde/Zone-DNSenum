# Zone-DNSenum

Zone-DNSenum is a Python-based tool for recursive DNS enumeration. It attempts AXFR (Zone Transfer) queries first and falls back to dictionary-based brute-force if AXFR fails. The tool recursively scans newly discovered subdomains up to a configurable depth limit.

## Features

- Complete DNS Zone Transfer (AXFR) attempts.
- Multi-threaded subdomain brute-forcing.
- Recursive enumeration of discovered subdomains.
- Output saving capability.
- Asynchronous queuing system for performance.

## Installation

### pipx (recommended)

```bash
pipx install git+https://github.com/Goultarde/Zone-DNSenum.git
```

### pip

```bash
pip install git+https://github.com/Goultarde/Zone-DNSenum.git
```

### From source

```bash
git clone https://github.com/Goultarde/Zone-DNSenum.git
cd Zone-DNSenum
pip install .
```

Once installed, the `zone-dnsenum` command is available globally.

## Usage

```bash
zone-dnsenum -d "$DOMAIN" -s "$IP" -w "$SUBDOMAIN_WORDLIST_PATH" [options]
```

### Arguments

- `-d, --domain`   : Target domain(s) or file containing a list of domains (required)
- `-s, --server`   : DNS Server IP to query (required)
- `-w, --wordlist` : Path to the subdomain wordlist (required)
- `-t, --threads`  : Number of threads for brute-forcing (default: 40)
- `--depth`        : Maximum enumeration depth (1 = direct subdomains; default: 3)
- `-o, --output`   : File to save the enumerated subdomains and IP addresses

### Example

```bash
zone-dnsenum -d "$DOMAIN" -s "$DNS_SERVER_IP" -w "$SUBDOMAIN_WORDLIST_PATH" -o results.txt
```
