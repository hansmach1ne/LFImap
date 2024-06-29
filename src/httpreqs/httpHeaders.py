"""httpHeaders"""
import random
from src.utils.arguments import init_args


def addHeader(headers, newKey, newVal):
    """"Add a header to the dict"""
    headers[newKey] = newVal
    return headers


def delHeader(headers, key):
    """Remove header from the dict"""
    headers.pop(key)
    return headers


def initHttpHeaders():
    """Init the header dict"""
    args  = init_args()
    headers = {}
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.3",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.",
        "Mozilla/5.0 (X11; Linux i686; rv:127.0) Gecko/20100101 Firefox/127.0",
        "Mozilla/5.0 (X11; U; Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Safari/537.3",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/0.2.153.1 Safari/525.19",
    ]

    if args['agent']:
        headers["User-Agent"] = args['agent']
    else:
        headers["User-Agent"] = random.choice(user_agents)
    if args['referer']:
        headers["Referer"] = args['referer']

    headers["Accept"] = "*/*"
    headers["Connection"] = "Close"

    return headers
