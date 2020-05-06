# About grepaddr
Grepaddr takes input from stdin and extracts different kinds of addresses from stdin.

Because the script uses regexp, it's very common to get false positives.
The options --resolve (FQDNs only) --iana and --private can be used to reduce the number of false positives.

# Install
Grepaddr should be able to run with a default Kali Linux installation without installing additional Python packages. If you're running into trouble running grepaddr, please drop me an issue and I'll try to fix it :)

# Usage
```
usage: grepaddr [-h] [-fqdn] [-srv] [-email] [--port] [--iana] [--private] [--resolve] [-ipv4] [-cidr4] [-ipv6] [-cidr6] [-mac]
[-url] [-relurl] [-csv <file>] [-decode <rounds>] [-unslash <rounds>]

Use grepaddr to extract different kinds of addresses from stdin. If no arguments are given, addresses of all types are shown.

optional arguments:
  -h, --help         show this help message and exit
  -fqdn              Extract fully qualified domain names.
  -srv               Extract DNS SRV records.
  -email             Extract e-mail addresses.
  --port             Include :port for extraction.
  --iana             Extract FQDNs with IANA registered TLDs , use with -fqdn, -srv or -email . No impact on other options.
  --private          Extract FQDNs with TLDs for private use, use with -fqdn. No impact on other options.
  --resolve          Display only those FQDNs that can be resolved. Cannot be used together with --iana or --private.
                     No impact on other options.
  -ipv4              Extract IP version 4 addresses.
  -cidr4             Extract IP version 4 addresses in CIDR notation.
  -ipv6              Extract IP version 6 addresses.
  -cidr6             Extract IP version 6 addresses in CIDR notation.
  -mac               Extract MAC addresses.
  -url               Extract URLs (FQDN, IPv4, IPv6, mailto and generic detection of schemes).
  -relurl            Extract relative URLs.
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
Want to extract FQDNs and show only resolved FQDNs URLs needed to be decoded first, just run:
```
wget -qO - https://twitter.com|grepaddr -fqdn --resolve --decode 1
```
# Contribute?
Do you have some usefull additions to the script, please send in a pull request to help make this script better :)
