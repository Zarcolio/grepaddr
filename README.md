![](https://img.shields.io/github/license/Zarcolio/grepaddr) ![](https://badges.pufler.dev/visits/Zarcolio/grepaddr) ![](https://img.shields.io/github/stars/Zarcolio/grepaddr) ![](https://img.shields.io/github/forks/Zarcolio/grepaddr) ![](https://img.shields.io/github/issues/Zarcolio/grepaddr) ![](https://img.shields.io/github/issues-closed-raw/Zarcolio/grepaddr) ![](https://img.shields.io/github/issues-pr/Zarcolio/grepaddr) ![](https://img.shields.io/github/issues-pr-closed-raw/Zarcolio/grepaddr)

# About [GrepAddr](https://github.com/Zarcolio/grepaddr) 
GrepAddr takes input from stdin and extracts different kinds of addresses from stdin like URLs, IP addresses, e-mail addresses, MAC addresses and more.

Because the script uses regexp, it's very common to get false positives for FQDNs.
The options --resolve (FQDNs only) --iana and --private can be used to reduce the number of false positives.

# Why use GrepAddr?
Several tools and scripts exist on the internet which similar functionality but usually only for a single address type, for example xurlsx, xpath-url-extraction and relative-url-extractor. GrepAddr can extract a large number of address types. You can use GrepAddr when doing a pen test or CTF, or when persuing a bug bounty.

# Install
GrepAddr should be able to run with a default Kali Linux installation without installing additional Python packages. 
Just run:
```
git clone https://github.com/Zarcolio/grepaddr
cd grepaddr
sudo bash install.sh
```
When using the installer in an automated environment, use the following command for an automated installation:
```
sudo bash install.sh -auto
```

If you're running into trouble running grepaddr, please drop me an issue and I'll try to fix it :)

# Usage
```
usage: grepaddr [-h] [-fqdn] [-srv] [-email] [--port] [--iana] [--private] [--resolve] [-ipv4] [-cidr4]
[-ipv6] [-cidr6] [-mac] [-url] [-relurl] [--baseurl <url>] [--basetag] [-csv <file>] [-decode <rounds>] 
[-unescape <rounds>]

Use GrepAddr to extract different kinds of addresses from stdin. If no arguments are given, addresses
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
When looking for URLs from the current user hive within Windows' registry, run these commands:

Within Windows:
```
reg export HKCU hkcu.reg
```
Within your favorite Unix-like OS:
```
dos2unix -f hkcu.reg
strings hkcu.reg|grepaddr -url
```


# Contribute?
Do you have some usefull additions to GrepAddr:

* [![PR's Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat)](https://github.com/Zarcolio/grepaddr/pulls) 
* [![Twitter](https://img.shields.io/twitter/url/https/twitter.com/zarcolio.svg?style=social&label=Contact%20me)](https://twitter.com/zarcolio)
