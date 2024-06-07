import time
import requests
from src.utils.arguments import args, logging
import src.httpreqs.httpHeaders

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
        if(args.delay):
            time.sleep(args.delay/1000)
    except KeyboardInterrupt:
        logging.info("\nKeyboard interrupt detected. Exiting...")
        lfimap_cleanup()
    except requests.exceptions.InvalidSchema:
        if(args.verbose): logging.info("InvalidSchema exception detected. Server doesn't understand the parameter value.")
    except:
        raise

    return res, doContinue
