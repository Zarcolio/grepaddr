#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import re
import argparse
import signal
import requests
import urllib
import codecs
import socket

def signal_handler(sig, frame):
        print("\nCtrl-C detected, exiting...\n")
        sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

ESCAPE_SEQUENCE_RE = re.compile(r'''
    ( \\U........      # 8-digit hex escapes
    | \\u....          # 4-digit hex escapes
    | \\x..            # 2-digit hex escapes
    | \\[0-7]{1,3}     # Octal escapes
    | \\N\{[^}]+\}     # Unicode characters by name
    | \\[\\'"abfnrtv]  # Single-character escapes
    )''', re.UNICODE | re.VERBOSE)

def unslash_escapes(s):
    # replace = hack because / and . cannot be unescaped:
    s = s.replace("\/", "/")
    s = s.replace("\.", ".")
    s = s.replace("\:", ":")
    s = s.replace("\;", ";")

    def unslash_match(match):
        try:
            return codecs.decode(match.group(0), 'unicode-escape')
        except:
            pass

    return ESCAPE_SEQUENCE_RE.sub(unslash_match, s)

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

# To do: host:port & ip:port

def Fqdn(strInput):
    # RFC compliant FQDN, regex by https://github.com/guyhughes/fqdn:
    regex = r"((?!-)[-A-Z\d]{1,62}(?<!-)\.)+[A-Z]{1,62}"
    if aArguments.port:
        regex += "(:(6553[0-5]|655[0-2][0-9]\d|65[0-4](\d){2}|6[0-4](\d){3}|[1-5](\d){4}|[1-9](\d){0,3})[\w|\d])?"
    matches = re.finditer(regex, strInput, re.IGNORECASE)
    lMatches = []
    for matchNum, match in enumerate(matches, start=1):
        lMatches.append( "{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
    return lMatches

def Srv(strInput):
    regex = r"((?!-)(_[-A-Z\d]{1,62}\.){1,2}[-A-Z\d]{1,62}(?<!-)\.)+[A-Z]{1,62}"
    matches = re.finditer(regex, strInput, re.IGNORECASE)
    lMatches = []
    for matchNum, match in enumerate(matches, start=1):
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
        lMatches.append( "{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
    return lMatches

def MacAddress2(strInput):
    regex = r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})"
    matches = re.finditer(regex, strInput, re.IGNORECASE)
    lMatches = []
    for matchNum, match in enumerate(matches, start=1):
        lMatches.append( "{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
    return lMatches

def IpV4(strInput):
    regex = r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    matches = re.finditer(regex, strInput, re.IGNORECASE)
    lMatches = []
    for matchNum, match in enumerate(matches, start=1):
        lMatches.append( "{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
    return lMatches

def Cidr4(strInput):
    regex = r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(3[0-2]|[1-2][0-9]|[0-9])"
    matches = re.finditer(regex, strInput, re.IGNORECASE)
    lMatches = []
    for matchNum, match in enumerate(matches, start=1):
        lMatches.append( "{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
    return lMatches

def IpV6(strInput):
    regex = r"(?:|(?<=\s))(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(?=\s|)"
    matches = re.finditer(regex, strInput, re.IGNORECASE)
    lMatches = []
    for matchNum, match in enumerate(matches, start=1):
        lMatches.append( "{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
    return lMatches

def Cidr6(strInput):
    regex = r"s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*\/(12[0-8]|1[0-1][0-9]|[1-9][0-9]|[0-9])?"
    matches = re.finditer(regex, strInput, re.IGNORECASE)
    lMatches = []
    for matchNum, match in enumerate(matches, start=1):
        lMatches.append( "{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
    return lMatches

def Urls(strInput):
    #regex = r"(([a-zA-Z][a-zA-Z0-9+-.]*\:\/\/)|mailto\:)[a-zA-Z0-9\.\/\?\:@\-_=#]+\.([a-zA-Z]){2,6}([a-zA-Z0-9\.\&\/\?\:@\+\-_=#%;])*"
    regex = r"(([a-zA-Z][a-zA-Z0-9+-.]*\:\/\/)|mailto|data\:)[a-zA-Z0-9\.\/\?\:@\-_=#]([a-zA-Z]){2,6}([a-zA-Z0-9\.\&\/\?\:@\+\-_=#%;,])*"
    matches = re.finditer(regex, strInput, re.IGNORECASE)
    lMatches = []
    for matchNum, match in enumerate(matches, start=1):
        lMatches.append( "{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
    return lMatches

def UrlsIpV6(strInput):
    regex = r"(?:|(?<=\s))([a-zA-Z][a-zA-Z0-9+-.]*\:\/\/)(\[)(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\])(\])([a-zA-Z0-9\.\&\/\?\:@\-_=#%;])*(?=\s|)"
    matches = re.finditer(regex, strInput, re.IGNORECASE)
    lMatches = []
    for matchNum, match in enumerate(matches, start=1):
        lMatches.append( "{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
    return lMatches

# To do: catch: <href="//abs.twimg.com/favicons/favicon.ico>
def RelUrls(strInput):
    regex = r"(?:url\(|<(?:applet|area|audio|base|blockquote|body|button|command|del|embed|form|frame|head|html|iframe|img|image|ins|link|object|script|q|source|track|video)[^>]+(?:[<\s]action|background|cite|classid|codebase|data|formaction|href|icon|longdesc|manifest|poster|profile|src|usemap)\s*=\s*)(?!['\"]?(?:data|([a-zA-Z][a-zA-Z0-9+-.]*\:\/\/)))['\"]?([^'\"\)\s>]+)"
    matches = re.finditer(regex, strInput, re.IGNORECASE)
    lMatches = []
    for matchNum, match in enumerate(matches, start=1):
        lMatches.append(match.group(2))
        #lMatches.append("{match}".format(matchNum=matchNum, start=match.start(), end=match.end(), match=match.group()))

    return lMatches

def Email(strInput):
    regex = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
    matches = re.finditer(regex, strInput, re.IGNORECASE)
    lMatches = []
    for matchNum, match in enumerate(matches, start=1):
        lMatches.append( "{match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
    return lMatches

# Get some commandline arguments:
sArgParser=argparse.ArgumentParser(description='Use grepaddr to extract different kinds of addresses from stdin. If no arguments are given, addresses of all types are shown.')
sArgParser.add_argument('-fqdn', help='Extract fully qualified domain names.', action="store_true")
sArgParser.add_argument('-srv', help='Extract DNS SRV records.', action="store_true")
sArgParser.add_argument('-email', help='Extract e-mail addresses.', action="store_true")
sArgParser.add_argument('--port', help='Include :port for extraction.', action="store_true")
sArgParser.add_argument('--iana', help='Extract FQDNs with IANA registered TLDs , use with -fqdn, -srv or -email . No impact on other options.', action="store_true")
sArgParser.add_argument('--private', help='Extract FQDNs with TLDs for private use, use with -fqdn. No impact on other options.', action="store_true")
sArgParser.add_argument('--resolve', help='Display only those FQDNs that can be resolved. Cannot be used together with --iana or --private. No impact on other options.', action="store_true")
sArgParser.add_argument('-ipv4', help='Extract IP version 4 addresses.', action="store_true")
sArgParser.add_argument('-cidr4', help='Extract IP version 4 addresses in CIDR notation.', action="store_true")
sArgParser.add_argument('-ipv6', help='Extract IP version 6 addresses.', action="store_true")
sArgParser.add_argument('-cidr6', help='Extract IP version 6 addresses in CIDR notation.', action="store_true")
sArgParser.add_argument('-mac', help='Extract MAC addresses.', action="store_true")
sArgParser.add_argument('-url', help='Extract URLs (FQDN, IPv4, IPv6, mailto and generic detection of schemes).', action="store_true")
sArgParser.add_argument('-relurl', help='Extract relative URLs.', action="store_true")
sArgParser.add_argument('-csv', metavar="<file>", help='Save addresses found to this CSV file.')
sArgParser.add_argument('-decode', metavar="<rounds>", help='URL decode input this many times before extracting FQDNs.')
sArgParser.add_argument('-unslash', metavar="<rounds>", help='Unescape slashes within input this many times before extracting FQDNs.')

aArguments=sArgParser.parse_args()

if aArguments.fqdn == False and aArguments.srv == False and aArguments.ipv4 == False and aArguments.cidr4 == False and aArguments.ipv6 == False and aArguments.cidr6 == False and aArguments.mac == False and aArguments.url == False and aArguments.relurl == False and aArguments.email == False:
    aArguments.fqdn = True
    aArguments.srv = True
    aArguments.ipv4 = True
    aArguments.cidr4 = True
    aArguments.ipv6 = True
    aArguments.cidr6 = True
    aArguments.mac = True
    aArguments.url = True
    aArguments.relurl = True
    aArguments.email = True

if (aArguments.iana or aArguments.private) and (aArguments.resolve):
    print("Arguments --iana and --private cannot be used in conjuction with -resolves.")
    print()
    sArgParser.print_help()
    sys.exit(2)

if (aArguments.private or aArguments.iana) and (not aArguments.fqdn and not aArguments.email and not aArguments.srv): #  or (aArguments.private and not aArguments.fqdn) or (not aArguments.private and aArguments.fqdn):
    print("Arguments --iana and --private are used in conjuction with -fqdn -srv or -email.")
    print()
    sArgParser.print_help()
    sys.exit(2)

lIanaTlds = GetIanaTlds()
lPrivateTlds = GetPrivateTlds()

x = 0
dResults = {}
#Read from standard input:
for strInput in sys.stdin:
    iCountDecode = 0
    # Default to never URL decode:
    if not aArguments.decode:
        decodingRounds = 0
    else:
        decodingRounds = int(aArguments.decode)

    for iCountDecode in range(0, decodingRounds+1):
        if iCountDecode>0:
            strInput = urllib.parse.unquote(strInput)

        # To prevent 2F in hostnames originating from http:// -> %2F when used with -decode:
        if decodingRounds == 1 or iCountDecode == decodingRounds:
            # Changes in this section should also be done in the unslash section
            if aArguments.fqdn:
                lMatchesFqdn = Fqdn(strInput)
                for sFqdn in lMatchesFqdn:
                    if aArguments.resolve:
                        try:
                            lResolvedFqdn = socket.gethostbyname(sFqdn)    # lResolvedFqdn is not used.
                            dResults[sFqdn] = "FQDN;" + sFqdn
                        except:
                            pass
                    else:
                        if aArguments.iana:
                            if EndsWithIanaTld(sFqdn):
                                dResults[sFqdn] = "FQDN;" + sFqdn

                        if aArguments.private:
                            if EndsWithPrivateTld(sFqdn):
                                dResults[sFqdn] = "FQDN;" + sFqdn

                        if not aArguments.iana and not aArguments.private:
                            dResults[sFqdn] = "FQDN;" + sFqdn

        iCountUnslash = 0
        # Default to never unslash:
        if not aArguments.unslash:
            UnslashRounds = 0
        else:
            UnslashRounds = int(aArguments.unslash)

        for iCountUnslash in range(0, UnslashRounds + 1):
            if iCountUnslash > 0:
                strInput = unslash_escapes(strInput)

            # To prevent remants in hostnames originating from escaped characters:
            if UnslashRounds == 1 or iCountUnslash == UnslashRounds:
                # Implement same changes as in the decode section:
                if aArguments.fqdn:
                    lMatchesFqdn = Fqdn(strInput)
                    for sFqdn in lMatchesFqdn:
                        if aArguments.resolve:
                            try:
                                lResolvedFqdn = socket.gethostbyname(sFqdn)  # lResolvedFqdn is not used.
                                dResults[sFqdn] = "FQDN;" + sFqdn
                            except:
                                pass
                        else:
                            if aArguments.iana:
                                if EndsWithIanaTld(sFqdn):
                                    dResults[sFqdn] = "FQDN;" + sFqdn

                            if aArguments.private:
                                if EndsWithPrivateTld(sFqdn):
                                    dResults[sFqdn] = "FQDN;" + sFqdn

                            if not aArguments.iana and not aArguments.private:
                                dResults[sFqdn] = "FQDN;" + sFqdn
        """
        if aArguments.srv:
            lMatchesSrv = Srv(strInput)
            for sSrv in lMatchesSrv:
                dResults[sSrv] = "SRV;" + sSrv
        """
        if aArguments.srv:
            lMatchesSrv = Srv(strInput)
            if aArguments.iana:
                for sSrv in lMatchesSrv:
                    if EndsWithIanaTld(sSrv):
                        dResults[sSrv] = "SRV;" + sSrv
            else:
                for sSrv in lMatchesSrv:
                    dResults[sSrv] = "SRV;" + sSrv





        if aArguments.mac:
            lMatchesMac1 = MacAddress1(strInput)
            for sMac1 in lMatchesMac1:
                dResults[sMac1] = "MAC;" + sMac1

            lMatchesMac2 = MacAddress2(strInput)
            for sMac2 in lMatchesMac2:
                dResults[sMac2] = "MAC;" + sMac2

        if aArguments.cidr4:
            lMatchesCidr4 = Cidr4(strInput)
            for sCidr4 in lMatchesCidr4:
                dResults[sCidr4] = "IPv4 CIDR;" + sCidr4

        if aArguments.ipv4:
            lMatchesIpV4 = IpV4(strInput)
            for sIpV4 in lMatchesIpV4:
                if aArguments.cidr4:
                    #if [s for s in lMatchesCidr4 if sIpV4 + "/" not in s] :
                    dResults[sIpV4] = "IPv4;" + sIpV4
                else:
                    dResults[sIpV4] = "IPv4;" + sIpV4

        if aArguments.cidr6:
            lMatchesCidr6 = Cidr6(strInput)
            for sCidr6 in lMatchesCidr6:
                dResults[sCidr6] = "IPv6 CIDR;" + sCidr6

        if aArguments.ipv6:
            lMatchesIpV6 = IpV6(strInput)
            for sIpV6 in lMatchesIpV6:
                if aArguments.cidr6:
                    #if [s for s in lMatchesCidr6 if sIpV6 + "/" not in s] :
                    dResults[sIpV6] = "IPv6;" + sIpV6
                else:
                    dResults[sIpV6] = "IPv6;" + sIpV6

        if aArguments.url:
            lMatchesUrl = Urls(strInput)
            for sUrl in lMatchesUrl:
                    dResults[sUrl] = "URL;" + sUrl

        if aArguments.url:
            lMatchesUrl6 = UrlsIpV6(strInput)
            for sUrl6 in lMatchesUrl6:
                dResults[sUrl6] = "URL;" + sUrl6

        if aArguments.relurl:
            lMatchesRelUrl = RelUrls(strInput)
            for sRelUrl in lMatchesRelUrl:
                dResults[sRelUrl] = "URL;" + sRelUrl

        if aArguments.email:
            lMatchesEmail = Email(strInput)
            if aArguments.iana:
                for sEmail in lMatchesEmail:
                    if EndsWithIanaTld(sEmail):
                        dResults[sEmail] = "E-mail;" + sEmail
            else:
                for sEmail in lMatchesEmail:
                    dResults[sEmail] = "E-mail;" + sEmail

for item in dResults.keys():
    print(item)

if aArguments.csv:
    fCsv = open(aArguments.csv, 'w', buffering=1)
    for item in dResults.values():
        fCsv.write(item + "\n")