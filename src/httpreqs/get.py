import time
import requests
from src.utils.arguments import args

def GET(url, headers, proxy, exploitType, exploitMethod, exploit = False):
    doContinue = True
    res = None

    try:
        if(exploit):
            stats["getRequests"] += 1
            if(args.method): res = requests.request(args.method, url, data = "", headers = headers, proxies = proxy, verify = False)
            else: res = requests.get(url, headers = headers, data = "", proxies = proxy, verify = False)
        else:
            stats["getRequests"] += 1
            if(args.method): res = requests.request(args.method, url, data = "", headers = headers, proxies = proxy, verify = False)
            else: res = requests.get(url, headers = headers, data = "", proxies = proxy, verify = False)
            if(init(res, "GET", exploitType, url, "", headers, exploitMethod)):
                doContinue = False
        if(args.delay):
            time.sleep(args.delay/1000)
    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...")
        lfimap_cleanup()
    except requests.exceptions.InvalidSchema:
        if(args.verbose): print("InvalidSchema exception detected. Server doesn't understand the parameter value.")
    except:
        pass
        
    return res, doContinue