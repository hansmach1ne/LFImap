"""GET"""
import time
import requests
from src.utils.arguments import init_args


def GET(url, headers, proxy, exploitType, exploitMethod, exploit=False):
    args  = init_args()
    doContinue = True
    res = None

    try:
        if exploit:
            stats["getRequests"] += 1
            if args['method']:
                res = requests.request(
                    args['method'],
                    url,
                    data="",
                    headers=headers,
                    proxies=proxy,
                    verify=False,
                    timeout=args['maxTimeout']
                )
            else:
                res = requests.get(
                    url, headers=headers, data="", proxies=proxy, verify=False,
                    timeout=args['maxTimeout']
                )
        else:
            stats["getRequests"] += 1
            if args['method']:
                res = requests.request(
                    args['method'],
                    url,
                    data="",
                    headers=headers,
                    proxies=proxy,
                    verify=False,
                    timeout=args['maxTimeout']
                )
            else:
                res = requests.get(
                    url, headers=headers, data="", proxies=proxy, verify=False,
                    timeout=args['maxTimeout']
                )
            if init(res, "GET", exploitType, url, "", headers, exploitMethod):
                doContinue = False
        if args['delay']:
            time.sleep(args['delay'] / 1000)
    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...", flush = True)
        lfimap_cleanup()
    except requests.exceptions.InvalidSchema:
        if args['verbose']:
            print(
                "InvalidSchema exception detected. Server doesn't understand the parameter value.",
                flush = True
            )
    except:
        pass

    return res, doContinue
