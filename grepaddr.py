#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -fqdn -srv -ipv4 -ipv6 -ipv4cidr -ipv6cidr -mac -url.bare -url.get -url.id

import sys
import os
import re
import urllib.parse
import argparse
import signal
import requests

def signal_handler(sig, frame):
        print("\nCtrl-C detected, exiting...\n")
        sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def GetIanaTlds():
    # Get official TLD:
    sTldUrl = "https://data.iana.org:443/TLD/tlds-alpha-by-domain.txt"
    xheaders = {"User-Agent": "Python/grepaddress1.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.7,nl;q=0.3", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1", "Cache-Control": "max-age=0"}
    session = requests.get(sTldUrl, headers=xheaders)
    lOfficialTlds = session.text.lower().split("\n")
    return [x for x in lOfficialTlds if x != "" and not '#' in x]

def GetPrivateTlds():
    # Read private TLDs from file:
    fTlds = os.path.dirname(os.path.realpath(__file__)) + "/privatetlds.txt"
    try:
        f = open(fTlds, 'r')
        privatetlds = f.read().splitlines()
        f.close()
        return [x for x in privatetlds if x != "" and not '#' in x]
    except FileNotFoundError:
        print("File with TLDs named " + fTlds + " was not found.")
        sys.exit(2)

def JoinTlds(lOfficialTlds, privatetlds):
    # Join official and private TLDs:
    alltlds = lOfficialTlds + privatetlds
    alltlds = list(filter(lambda x: x != "", alltlds))
    return alltlds

def Fqdn(strInput):
    # RFC compliant FQDN, regex by https://github.com/guyhughes/fqdn:
    regex = r"((?!-)[-A-Z\d]{1,62}(?<!-)\.)+[A-Z]{1,62}"
    matches = re.finditer(regex, strInput, re.IGNORECASE)
    lMatches = []
    for matchNum, match in enumerate(matches, start=1):
        #print ("{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
        lMatches.append( "{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
    return lMatches

def EndsWithIanaTld(sUrl):
    for sTld in lIanaTlds:
        if sUrl.endswith("." + sTld):
            return sUrl

def EndsWithPrivateTld(sUrl):
    for sTld in lPrivateTlds:
        if sUrl.endswith("." + sTld):
            return sUrl

def MacAddress1(strInput):
    regex = r"([0-9a-fA-F][0-9a-fA-F][:-]){5}([0-9a-fA-F][0-9a-fA-F])"
    matches = re.finditer(regex, strInput, re.IGNORECASE)
    lMatches = []
    for matchNum, match in enumerate(matches, start=1):
        #print ("{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
        lMatches.append( "{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
    return lMatches


def MacAddress2(strInput):
    regex = r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})"
    matches = re.finditer(regex, strInput, re.IGNORECASE)
    lMatches = []
    for matchNum, match in enumerate(matches, start=1):
        #print ("{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
        lMatches.append( "{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
    return lMatches

def IpV4(strInput):
    regex = r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    matches = re.finditer(regex, strInput, re.IGNORECASE)
    lMatches = []
    for matchNum, match in enumerate(matches, start=1):
        #print ("{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
        lMatches.append( "{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
    return lMatches

def Cidr4(strInput):
    regex = r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(3[0-2]|[1-2][0-9]|[0-9])"
    matches = re.finditer(regex, strInput, re.IGNORECASE)
    lMatches = []
    for matchNum, match in enumerate(matches, start=1):
        #print ("{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
        lMatches.append( "{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
    return lMatches

def IpV6(strInput):
    regex = r"(?:^|(?<=\s))(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(?=\s|$)"
    matches = re.finditer(regex, strInput, re.IGNORECASE)
    lMatches = []
    for matchNum, match in enumerate(matches, start=1):
        #print ("{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
        lMatches.append( "{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
    return lMatches

def Cidr6(strInput):
    regex = r"s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*\/(12[0-8]|1[0-1][0-9]|[1-9][0-9]|[0-9])?"
    matches = re.finditer(regex, strInput, re.IGNORECASE)
    lMatches = []
    for matchNum, match in enumerate(matches, start=1):
        #print ("{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
        lMatches.append( "{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
    return lMatches

def Urls(strInput):
    regex = r"^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?"
    matches = re.finditer(regex, strInput, re.IGNORECASE)
    lMatches = []
    for matchNum, match in enumerate(matches, start=1):
        #print ("{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
        lMatches.append( "{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
    return lMatches


def Email(strInput):
    regex = r"^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$"
    matches = re.finditer(regex, strInput, re.IGNORECASE)
    lMatches = []
    for matchNum, match in enumerate(matches, start=1):
        #print ("{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
        lMatches.append( "{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
    return lMatches

# Get some commandline arguments:
sArgParser=argparse.ArgumentParser(description='Use grepaddr to extract different kinds of addresses from stdin. If no arguments are given, addresses of all type are shown.')
sArgParser.add_argument('-fqdn', help='Extract fully qualified domain names.', action="store_true")
sArgParser.add_argument('--iana', help='Extract FQDNs with TLDs registered with IANA, use with -fqdn.', action="store_true")
sArgParser.add_argument('--private', help='Extract FQDNs with TLDs for private use, use with -fqdn.', action="store_true")
sArgParser.add_argument('-srv', help='Extract DNS SRV records.', action="store_true")
sArgParser.add_argument('-ipv4', help='Extract IP version 4 addresses.', action="store_true")
sArgParser.add_argument('-cidr4', help='Extract IP version 4 addresses in CIDR notation.', action="store_true")
sArgParser.add_argument('-ipv6', help='Extract IP version 6 addresses.', action="store_true")
sArgParser.add_argument('-cidr6', help='Extract IP version 6 addresses in CIDR notation.', action="store_true")
sArgParser.add_argument('-mac', help='Extract MAC addresses.', action="store_true")
sArgParser.add_argument('-url', help='Extract URLS without query string.', action="store_true")
sArgParser.add_argument('-email', help='Extract URLS without query string.', action="store_true")

aArguments=sArgParser.parse_args()

if (aArguments.iana and not aArguments.fqdn) or (aArguments.private and not aArguments.fqdn):
    print("Arguments --iana and --private are used in conjuction with -fqdn.")
    print()
    sArgParser.print_help()
    sys.exit(2)

if len(sys.argv) == 1:
    aArguments.fqdn = True
    aArguments.iana = True
    aArguments.private = True
    aArguments.srv = True
    aArguments.ipv4 = True
    aArguments.cidr4 = True
    aArguments.ipv6 = True
    aArguments.cidr6 = True
    aArguments.mac = True
    aArguments.url = True
    aArguments.email = True

lIanaTlds = GetIanaTlds()
lPrivateTlds = GetPrivateTlds()

#Read from standard input:
for strInput in sys.stdin:
    # Some URLs have double encoded values, so 2 times "unquote":
    strInput = urllib.parse.unquote(strInput)
    strInput = urllib.parse.unquote(strInput)
    lMatchesFqdn = Fqdn(strInput)    

    if aArguments.fqdn:
        lMatchesFqdn = Fqdn(strInput)
        for Fqdn in lMatchesFqdn:
            if aArguments.iana:
                if EndsWithIanaTld(Fqdn):
                    print(Fqdn)

            if aArguments.private:
                if EndsWithPrivateTld(Fqdn):
                    print(Fqdn)
                
            if not aArguments.iana and not aArguments.private:
                    print(Fqdn)

    if aArguments.mac:
        lMatchesMac1 = MacAddress1(strInput)
        for sMac1 in lMatchesMac1:
            print(sMac1)
    
        lMatchesMac2 = MacAddress2(strInput)
        for sMac2 in lMatchesMac2:
            print(sMac2)

    if aArguments.cidr4:
        lMatchesCidr4 = Cidr4(strInput)
        for sCidr4 in lMatchesCidr4:
            print(sCidr4)

    if aArguments.ipv4:
        lMatchesIpV4 = IpV4(strInput)
        for sIpV4 in lMatchesIpV4:
            if aArguments.cidr4:
                if [s for s in lMatchesCidr4 if sIpV4 + "/" not in s] :
                    print(sIpV4)
            else:
                print(sIpV4)

    if aArguments.cidr6:
        lMatchesCidr6 = Cidr6(strInput)
        for sCidr6 in lMatchesCidr6:
            print(sCidr6)

    if aArguments.ipv6:
        lMatchesIpV6 = IpV6(strInput)
        for sIpV6 in lMatchesIpV6:
            if aArguments.cidr6:
                if [s for s in lMatchesCidr6 if sIpV6 + "/" not in s] :
                    print(sIpV6)
            else:
                print(sIpV6)

# To do:
    if aArguments.url:
        lMatchesUrl = Urls(strInput)
#        for sUrl in lMatchesUrl:
#            print(sUrl)


    if aArguments.email:
        lMatchesEmail = Email(strInput)
        for sEmail in lMatchesEmail:
            print(sEmail)
