# About grepaddr
Grepaddr takes input from stdin and extracts different kinds of addresses from stdin like URLs, IP addresses, e-mail addresses, MAC addresses and more.

Because the script uses regexp, it's very common to get false positives for FQDNs.
The options --resolve (FQDNs only) --iana and --private can be used to reduce the number of false positives.

# Why grepaddr?
Several tools and scripts exist on the internet which similar functionality but usually only for a single address type, for example xurlsx, xpath-url-extraction and relative-url-extractor. Grepaddr can extract a large number of address types.

# Install
Grepaddr should be able to run with a default Kali Linux installation without installing additional Python packages. 
Just run:
```
git clone https://github.com/Zarcolio/grepaddr
cd grepaddr
bash install.sh
```
If you're running into trouble running grepaddr, please drop me an issue and I'll try to fix it :)

# Usage
```
usage: grepaddr [-h] [-fqdn] [-srv] [-email] [--port] [--iana] [--private] [--resolve] [-ipv4] [-cidr4]
[-ipv6] [-cidr6] [-mac] [-url] [-relurl] [--baseurl <url>] [--basetag] [-csv <file>] [-decode <rounds>] 
[-unescape <rounds>]

Use grepaddr to extract different kinds of addresses from stdin. If no arguments are given, addresses
of all types are shown.

optional arguments:
  -h, --help         show this help message and exit
  -fqdn              Extract fully qualified domain names.
  -srv               Extract DNS SRV records.
  -email             Extract e-mail addresses.
  --port             Include :port for extraction.
  --iana             Extract FQDNs with IANA registered TLDs , use with -fqdn, -srv or -email . No
                     impact on other options.
  --private          Extract FQDNs with TLDs for private use, use with -fqdn. No impact on other options.
  --resolve          Display only those FQDNs that can be resolved. Cannot be used together with
                     --iana or --private. No impact on other options.
  -ipv4              Extract IP version 4 addresses.
  -cidr4             Extract IP version 4 addresses in CIDR notation.
  -ipv6              Extract IP version 6 addresses.
  -cidr6             Extract IP version 6 addresses in CIDR notation.
  -mac               Extract MAC addresses.
  -url               Extract URLs (FQDN, IPv4, IPv6, mailto and generic detection of schemes).
  -relurl            Extract relative URLs.
  --basetag          Search for base URL in <BASE> and prepend it to URLS. Use with -url and/or -relurl.
  --baseurl <url>    Provide a base URL which is prepended to relative URLS starting at root. Use
                     with -url and/or -relurl.
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
Want to extract FQDNs with a private TLD, just run:
```
wget -qO - https://serverfault.com/questions/17255/top-level-domain-domain-suffix-for-private-network|grepaddr -fqdn --private
```
Want to extract FQDNs and show only resolved FQDNs URLs needed to be decoded first, just run:
```
wget -qO - https://twitter.com|grepaddr -fqdn --resolve --decode 1
```
Want to extract all addresses with the least chance of false positives without having to wait for resolving FQDNs:
```
wget -qO - https://twitter.com|grepaddr --iana
```
Want to extract all addresses and convert relative URLs starting at the root to an absolute URL:
```
wget -qO - https://twitter.com|grepaddr --base https://twitter.com
```
Want to extract addresses from a binary, use it together with strings:
```
string binary.ext|grepaddr
```

# Contribute?
Do you have some usefull additions to the script, please send in a pull request to help make this script better or contact me @ [Twitter](https://twitter.com/zarcolio) :)
