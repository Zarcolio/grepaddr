# About grepaddr
Grepaddr takes input from stdin and extracts different kinds of addresses from stdin.

# Install
Grepaddr should be able to run with a default Kali Linux installation without installing additional Python packages. If you're running into trouble running grepaddr, please drop me an issue and I'll try to fix it :)

# Usage
```
usage: grepaddr [-h] [-fqdn] [--iana] [--private] [-srv] [-ipv4] [-cidr4] [-ipv6] [-cidr6] [-mac] [-url]
[-relurl] [-email] [-csv <file>] [-decode <rounds>] [-unslash <rounds>]

Use grepaddr to extract different kinds of addresses from stdin. If no arguments are given, addresses of all 
types are shown.

optional arguments:
  -h, --help         show this help message and exit
  -fqdn              Extract fully qualified domain names.
  --iana             Extract FQDNs with IANA registered TLDs, use with -fqdn.
  --private          Extract FQDNs with TLDs for private use, use with -fqdn.
  -srv               Extract DNS SRV records.
  -ipv4              Extract IP version 4 addresses.
  -cidr4             Extract IP version 4 addresses in CIDR notation.
  -ipv6              Extract IP version 6 addresses.
  -cidr6             Extract IP version 6 addresses in CIDR notation.
  -mac               Extract MAC addresses.
  -url               Extract URLs (FQDN, IPv4, IPv6, mailto and generic detection of schemes).
  -relurl            Extract relative URLs.
  -email             Extract e-mail addresses.
  -csv <file>        Save addresses found to this CSV file.
  -decode <rounds>   URL decode input this many times before extracting FQDNs.
  -unslash <rounds>  Unescape slashes within input this many times before extracting FQDNs.
```
# Examples
It's really easy to extract all supported addresses from stdin, just run:
```
wget -qO - https://twitter.com|grepaddr -csv twitter.csv
```
Want to extract addresses of certain type? Choose one of the options, for example -mac and run:
```
wget -qO - https://nl.wikipedia.org/wiki/MAC-adres|grepaddr -mac
```
Want to extract FQDNs with a privacte TLD, just run:
```
wget -qO - https://serverfault.com/questions/17255/top-level-domain-domain-suffix-for-private-network|grepaddr -fqdn --private
```
