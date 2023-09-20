import urllib.parse as urlparse
from src.utils.arguments import args
from src.configs.config import *
from src.httpreqs.request import prepareRequest
from src.httpreqs.request import REQUEST
from src.utils.stats import stats
from src.utils import colors
import re

def test_heuristics(url, post):
    br = False
    o = urlparse.urlparse(url)

    if(args.verbose):
        print("\n" + colors.blue("[i]") + " Testing generic issues using heuristics...")

    tests = []
    # XSS check
    tests.append("lfi%3A31l%3Ef%3Cim%3B37%22%27ap")

    # (SSTI check - TODO research and make a polyglot
    #tests.append("%24%7B%7B1337%2A3113%7D%7D%27%24%7B1337%2A3113%7D")

    # Open Redirect -TODO make this check better
    
    #TODO store these in a separate file and make it bigger
    fiErrors = ["warning", "include(", "require(", "fopen(", "fpassthru(", "readfile(", "fread(", "fgets("]
    sqlErrors = ["you have an error in your sql syntax", "unclosed qutation mark after the character string",
            "you have an error in your sql syntax", "mysql_query(", "mysql_fetch_array(", 
            "mysql_fetch_assoc(", "mysql_fetch_field(", "mysql_fetch_field_direct(", "mysql_fetch_lengths(", 
            "mysql_fetch_object(", "mysql_fetch_row(", "mysql_fetch_all(", "mysql_prepare(", "mysql_info(",
            "mysql_real_query(", "mysql_stmt_init(", "mysql_stmt_execute("]

    for test in tests:
        vuln = False
        u, tempHeaders, postTest = prepareRequest(args.param, test, url, post)
        res, _ = REQUEST(u, tempHeaders, postTest, proxies, "INFO", "INFO")
        if("lfi:31l>f<im;37\"'ap" in res.text.lower()):
            vuln = True
            if(args.postreq and len(args.postreq) > 1): print(colors.green("[+]") + " XSS -> '" + u + "' -> HTTP POST -> '" + postTest + "' -> full reflection in response")
            else: print(colors.green("[+]") + " XSS -> '" + u + "' -> full reflection in response")

        else:
            # HREF
            if("lfi:" in res.text.lower()):
                pattern = r'href="LFI\:[^"]*'
                matches = re.findall(pattern, res.text.lower())
                if(len(matches) > 0 and vuln == False):
                    vuln = True
                    if(args.postreq and len(args.postreq) > 1): print(colors.green("[+]") + " XSS -> '" + u + "' -> HTTP POST -> '" + postTest + "' -> reflection in HREF attribute value")
                    else: print(colors.green("[+]") + " XSS -> '" + u + "' -> reflection in HREF atribute value")

            # ATTRIBUTE
            if("37\"'ap" in res.text.lower()):
                pattern = r'<[^>]+?\s*=\s*["\'][^"\']*?\b37"\'ap\b[^"\']*?["\'][^>]*>'
                matches = re.findall(pattern, res.text.lower())
                if(len(matches) > 0 and vuln == False):
                    vuln = True
                    if(args.postreq and len(args.postreq) > 1): print(colors.green("[+]") + " XSS -> '" + u + "' -> HTTP POST -> '" + postTest + "' -> reflection in tag attribute")
                    else: print(colors.green("[+]") + " XSS -> '" + u + "' -> reflection in tag atribute")
    

            #SCRIPT
            if("im;37" in res.text.lower()):
                pattern = r'\<script[\s\S]*im\;37[\s\S]*\<\/script\>'
                compiled_pattern = re.compile(pattern)
                #match = compiled_pattern.search(text)
                matches = re.findall(pattern, res.text.lower())
                if(len(matches) > 0 and vuln == False):
                    vuln = True
                    if(args.postreq and len(args.postreq) > 1): print(colors.green("[+]") + " XSS -> '" + u + "' -> HTTP POST -> '" + postTest + "' -> reflection in script context")
                    else: print(colors.green("[+]") + " XSS -> '" + u + "' -> reflection in script context")

            # TAG
            if("l>f<i" in res.text.lower() and vuln == False):
                vuln = True
                if(args.postreq and len(args.postreq) > 1): print(colors.green("[+]") + " XSS -> '" + u + "' -> HTTP POST -> '" + postTest + "' -> tag reflection in response")
                else: print(colors.green("[+]") + " XSS -> '" + u + "' -> tag reflection in response")
            
        if(vuln): 
            stats["vulns"] += 1
            br = True

            if("Content-Type" in res.headers):
                print("    Content-Type: '" + res.headers["Content-Type"] + "'")
            if("Content-Security-Policy" in res.headers):
                if("Content-Type" in res.headers):
                    print("\n")
                else: print("    Content-Security-Policy: '" + res.headers["Content-Security-Policy"] + "'")

        if("4162081" in res.text.lower()):
            if(args.postreq and len(args.postreq) > 1): print(colors.green("[+]") + " CSTI/SSTI -> '" + u + "' -> HTTP POST -> '" + postTest + "' -> {{1337*3113}} seems evaluated to 4162081")
            else: print(colors.green("[+]") + " CSTI/SSTI -> '" + u + "' -> expression {{1337*3113}} seems evaluated to 4162081")
            stats["vulns"] += 1
            br = True

        # Open redirect can be tested with initial request, instead of here. #TODO
        if(res.headers.get('Location') != None):
            if(res.headers.get('Location') == "l>f<i"):
                if(len(args.postreq) > 1): print(colors.green("[+]") + " Open redirect -> '" + u + "' -> HTTP POST -> '" + postTest + "'")
                else: print(colors.green("[+]") + " Open redirect -> '" + u + "'")
                stats["vulns"] += 1
                br= True

        if(args.quick or br): break

    #if(o.netloc not in checkedHosts):
    #checkedHosts.append(o.netloc)
    if(fiErrors[0] in res.text.lower()):
        for i in range(1,len(fiErrors)):
            if(fiErrors[i] in res.text.lower()):
                if(args.postreq and len(args.postreq) > 1): print(colors.green("[+]") + " Info disclosure -> '" + fiErrors[i] + "' error triggered -> '" + u + "' -> HTTP POST -> '" + postTest + "'")
                else: print(colors.green("[+]") + " Info disclosure -> '" + fiErrors[i] + "' error triggered -> '" + u + "'")
                stats["vulns"] += 1

        # Check for Sql errors
        for i in range(len(sqlErrors)):
            if(sqlErrors[i] in res.text.lower()):
                if(len(args.postreq) > 1): print(colors.green("[+]") + " Info disclosure -> '" + sqlErrors[i] + "' error detected -> '" + u + "' -> HTTP POST -> '" + postTest + "'")
                else: print(colors.green("[+]") + " Info disclosure -> '" + sqlErrors[i] + "' error detected -> '" + u + "'")
                stats["vulns"] += 1

    return