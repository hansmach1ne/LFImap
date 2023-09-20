import random
from src.utils.arguments import args
import src.utils.args_check

def addHeader(headers, newKey, newVal):
    headers[newKey] = newVal
    return headers

def delHeader(headers, key):
    headers.pop(key)
    return headers

def initHttpHeaders():
    headers = {}
    user_agents = [
            "Mozilla/5.0 (X11; U; Linux i686; it-IT; rv:1.9.0.2) Gecko/2008092313 Ubuntu/9.25 (jaunty) Firefox/3.8",
            "Mozilla/5.0 (X11; Linux i686; rv:2.0b3pre) Gecko/20100731 Firefox/4.0b3pre",
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.6)",
            "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en)",
            "Mozilla/3.01 (Macintosh; PPC)",
            "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.9)",
            "Mozilla/5.0 (X11; U; Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01",
            "Opera/8.00 (Windows NT 5.1; U; en)",
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/0.2.153.1 Safari/525.19"
            ]                                                                                                                                                                             

    if(args.agent):
        headers['User-Agent'] = args.agent                                                                                                                                                     
    else:
        headers['User-Agent'] = random.choice(user_agents)                                                                                                                                      
    if(args.referer):
        headers['Referer'] = args.referer

    headers['Accept'] = '*/*'
    headers['Connection'] = 'Close'

    return headers