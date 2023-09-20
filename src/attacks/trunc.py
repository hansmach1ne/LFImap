from src.utils.arguments import args
from src.httpreqs.request import prepareRequest
from src.httpreqs.request import REQUEST
from src.configs.config import *
from src.utils import colors

def test_trunc(url, post):
    if(args.verbose):
        print(colors.blue("[i]") + " Testing path truncation using '" + args.truncWordlist + "' wordlist...")
    i = 0
    with open(args.truncWordlist, "r", encoding='utf-8') as f:
        for line in f:
            line = line.replace("\n", "")
            u, reqHeaders, postTest = prepareRequest(args.param, line, url, post)
            # Because of some unicode tests that we do, (wide N for nodejs apps..)
            #TODO
            if(postTest):
                postTest = postTest.encode("utf-8")
            _, br = REQUEST(u, reqHeaders, postTest, proxies, "LFI", "TRUNC")
            if(not br): return
            if(i == 1 and args.quick): return
            i += 1
    return