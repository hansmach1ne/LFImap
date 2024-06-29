"""GET"""
import time
import requests
from src.utils.arguments import ArgumentHandler


def GET(url, headers, proxy, exploitType, exploitMethod, exploit=False):
    args = ArgumentHandler()
    doContinue = True
    res = None

    try:
        if exploit:
            stats["getRequests"] += 1
            if args.args['method']:
                res = requests.request(
                    args.args['method'],
                    url,
                    data="",
                    headers=headers,
                    proxies=proxy,
                    verify=False,
                    timeout=args.args['maxTimeout']
                )
            else:
                res = requests.get(
                    url, headers=headers, data="", proxies=proxy, verify=False,
                    timeout=args.args['maxTimeout']
                )
        else:
            stats["getRequests"] += 1
            if args.args['method']:
                res = requests.request(
                    args.args['method'],
                    url,
                    data="",
                    headers=headers,
                    proxies=proxy,
                    verify=False,
                    timeout=args.args['maxTimeout']
                )
            else:
                res = requests.get(
                    url, headers=headers, data="", proxies=proxy, verify=False,
                    timeout=args.args['maxTimeout']
                )
            if init(res, "GET", exploitType, url, "", headers, exploitMethod):
                doContinue = False
        if args.args['delay']:
            time.sleep(args.args['delay'] / 1000)
    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...")
        lfimap_cleanup()
    except requests.exceptions.InvalidSchema:
        if args.args['verbose']:
            print(
                "InvalidSchema exception detected. Server doesn't understand the parameter value."
            )
    except:
        pass

    return res, doContinue
