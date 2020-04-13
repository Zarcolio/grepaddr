# About grepaddr
Grepaddr takes input from stdin and extracts different kinds of addresses from stdin.

# Install
grepaddr should be able to run with a default Kali Linux installation without installing additional Python packages. If you're running into trouble running 2cmd, please drop me an issue and I'll try to fix it :)

# Usage
```
usage: grepaddr [-h] [-fqdn] [--iana] [--private] [-ipv4] [-cidr4] [-ipv6]
                [-cidr6] [-mac] [-url] [-email] [-csv CSV]

Use grepaddr to extract different kinds of addresses from stdin. If no
arguments are given, addresses of all type are shown.

optional arguments:
  -h, --help  show this help message and exit
  -fqdn       Extract fully qualified domain names.
  --iana      Extract FQDNs with TLDs registered with IANA, use with -fqdn.
  --private   Extract FQDNs with TLDs for private use, use with -fqdn.
  -ipv4       Extract IP version 4 addresses.
  -cidr4      Extract IP version 4 addresses in CIDR notation.
  -ipv6       Extract IP version 6 addresses.
  -cidr6      Extract IP version 6 addresses in CIDR notation.
  -mac        Extract MAC addresses.
  -url        Extract URLS without query string.
  -email      Extract URLS without query string.
  -csv CSV    Save addresses found in this CSV file.
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
