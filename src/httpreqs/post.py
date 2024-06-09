import time
import requests
from src.utils.arguments import process_arguments

def POST(url, headersData, postData, proxy, exploitType, exploitMethod, exploit = False):
    args = process_arguments()
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
        if(args.delay):
            time.sleep(args.delay/1000)
    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...")
        lfimap_cleanup()
    except requests.exceptions.InvalidSchema:
        if(args.verbose): print("InvalidSchema exception detected. Server doesn't understand the parameter value.")
    except:
        raise

    return res, doContinue
