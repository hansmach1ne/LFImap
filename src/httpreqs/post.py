"""POST"""
import time
import requests
from src.utils.arguments import args
from src.utils.stats import stats
from src.utils.cleanup import lfimap_cleanup
from src.configs import config


def POST(url, headersData, postData, proxy, exploitType, exploitMethod, exploit=False):
    """POST"""
    doContinue = True
    res = None

    try:
        if exploit:
            res = requests.post(
                url,
                data=postData,
                headers=headersData,
                proxies=proxy,
                verify=False,
                timeout=1,
            )
        else:
            stats["postRequests"] += 1
            res = requests.post(
                url,
                data=postData,
                headers=headersData,
                proxies=proxy,
                verify=False,
                timeout=1,
            )
            if init(
                res, "POST", exploitType, url, postData, headersData, exploitMethod
            ):
                doContinue = False

        if args.delay:
            time.sleep(args.delay / 1000)

    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...")
        lfimap_cleanup(config.webDir)

    except requests.exceptions.InvalidSchema:
        if args.verbose:
            print(
                "InvalidSchema exception detected. Server doesn't understand the parameter value."
            )
    except:
        raise

    return res, doContinue
