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
        print("\n" + colors.blue("[i]") + " Preparing to test misc issues using heuristics...")

    tests = []
    # XSS check
    tests.append("lfi%3A31l%3Ef%3Cim%3B37%22%27ap")
    # CRLF check
    tests.append("%0d%0aLfi:13CRLF37%250d%250aLfi%3A13CRLF37%25%30D%25%30ALfi%3A13CRLF37")

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
        if(args.verbose and "lfi%3A31l%3Ef%3Cim%3B37%22%27ap" in test): print(colors.blue("[.]") + " Testing for XSS...")
        if(args.verbose and "%0d%0a" in test): print(colors.blue("[.]") + " Testing for CRLF...")

        vuln = False
        u, tempHeaders, postTest = prepareRequest(args.param, test, url, post)
        res, _ = REQUEST(u, tempHeaders, postTest, proxies, "INFO", "INFO")

        # HREF
        if(res and "lfi:" in res.text.lower()):
            pattern = r'href="LFI\:[^"]*'
            matches = re.findall(pattern, res.text.lower())
            if(len(matches) > 0 and vuln == False):
                vuln = True
                if(args.postreq and len(args.postreq) > 1): print(colors.green("[+]") + " XSS -> '" + u + "' -> HTTP POST -> '" + postTest + "' -> reflection in HREF attribute value")
                else: print(colors.green("[+]") + " XSS -> '" + u + "' -> reflection in HREF atribute value")

        if(res and "lfi:31l>f<im;37\"'ap" in res.text.lower()):
            vuln = True
            if(args.postreq and len(args.postreq) > 1): print(colors.green("[+]") + " XSS -> '" + u + "' -> HTTP POST -> '" + postTest + "' -> full reflection in response")
            else: print(colors.green("[+]") + " XSS -> '" + u + "' -> full reflection in response")

        else:
            # HREF
            if(res and "lfi:" in res.text.lower()):
                pattern = r'href="LFI\:[^"]*'
                matches = re.findall(pattern, res.text.lower())
                if(len(matches) > 0 and vuln == False):
                    vuln = True
                    if(args.postreq and len(args.postreq) > 1): print(colors.green("[+]") + " XSS -> '" + u + "' -> HTTP POST -> '" + postTest + "' -> reflection in HREF attribute value")
                    else: print(colors.green("[+]") + " XSS -> '" + u + "' -> reflection in HREF atribute value")

            # ATTRIBUTE
            if(res and "37\"'ap" in res.text.lower()):
                pattern = r'<[^>]+?\s*=\s*["\'][^"\']*?\b37"\'ap\b[^"\']*?["\'][^>]*>'
                matches = re.findall(pattern, res.text.lower())
                if(len(matches) > 0 and vuln == False):
                    vuln = True
                    if(args.postreq and len(args.postreq) > 1): print(colors.green("[+]") + " XSS -> '" + u + "' -> HTTP POST -> '" + postTest + "' -> reflection in tag attribute")
                    else: print(colors.green("[+]") + " XSS -> '" + u + "' -> reflection in tag atribute")

            #SCRIPT
            if(res and "im;37" in res.text.lower()):
                pattern = r'\<script[\s\S]*im\;37[\s\S]*\<\/script\>'
                compiled_pattern = re.compile(pattern)
                #match = compiled_pattern.search(text)
                matches = re.findall(pattern, res.text.lower())
                if(len(matches) > 0 and vuln == False):
                    vuln = True
                    if(args.postreq and len(args.postreq) > 1): print(colors.green("[+]") + " XSS -> '" + u + "' -> HTTP POST -> '" + postTest + "' -> reflection in script context")
                    else: print(colors.green("[+]") + " XSS -> '" + u + "' -> reflection in script context")

            # TAG
            if(res and "l>f<i" in res.text.lower() and vuln == False):
                vuln = True
                if(args.postreq and len(args.postreq) > 1): print(colors.green("[+]") + " XSS -> '" + u + "' -> HTTP POST -> '" + postTest + "' -> tag reflection in response")
                else: print(colors.green("[+]") + " XSS -> '" + u + "' -> tag reflection in response")
        
        # CRLF
        if(res and any('13CRLF37' in value for value in res.headers.values()) and any('Lfi' in key for key in res.headers)):
            vuln = True
            if(args.postreq and len(args.postreq) > 1): print(colors.green("[+]") + " CRLF -> '" + u + "' -> HTTP POST -> '" + postTest + "' -> response splitting, 'lfi' header is present")
            else: print(colors.green("[+]") + " CRLF -> '" + u + "' -> response splitting, 'Lfi' header is present")

        if(vuln): 
            stats["vulns"] += 1
            br = True

            # Print CT, CSP details, because these could present another layer of security against XSS, CRLF
            if("Content-Type" in res.headers):
                print("    Content-Type: " + res.headers["Content-Type"])
            if("Content-Security-Policy" in res.headers):
                print("    Content-Security-Policy: " + res.headers["Content-Security-Policy"])

        # TODO check this and implement better testing
        if(res and "4162081" in res.text.lower()):
            if(args.postreq and len(args.postreq) > 1): print(colors.green("[+]") + " SSTI -> '" + u + "' -> HTTP POST -> '" + postTest + "' -> {{1337*3113}} seems evaluated to 4162081")
            else: print(colors.green("[+]") + " SSTI -> '" + u + "' -> template expression 1337*3113 seems evaluated to 4162081")
            stats["vulns"] += 1
            br = True

        if(args.quick or br): break

    if(args.verbose): print(colors.blue("[.]") + " Testing for error-based info leak...")

    if(res and fiErrors[0] in res.text.lower()):
        for i in range(1,len(fiErrors)):
            if(fiErrors[i] in res.text.lower()):
                if(args.postreq and len(args.postreq) > 1): print(colors.green("[+]") + " Info disclosure -> '" + fiErrors[i] + "' error triggered -> '" + u + "' -> HTTP POST -> '" + postTest + "'")
                else: print(colors.green("[+]") + " Info disclosure -> '" + fiErrors[i] + "' error triggered -> '" + u + "'")
                stats["vulns"] += 1

        # Check for Sql errors
        for i in range(len(sqlErrors)):
            if(res and sqlErrors[i] in res.text.lower()):
                if(len(args.postreq) > 1): print(colors.green("[+]") + " Info disclosure -> '" + sqlErrors[i] + "' error detected -> '" + u + "' -> HTTP POST -> '" + postTest + "'")
                else: print(colors.green("[+]") + " Info disclosure -> '" + sqlErrors[i] + "' error detected -> '" + u + "'")
                stats["vulns"] += 1

    # Open redirect check
    if(args.verbose): print(colors.blue("[.]") + " Testing for open redirect...")

    u, tempHeaders, postTest = prepareRequest(args.param, "/lfi/a/../", url, post)
    res, _ = REQUEST(u, tempHeaders, postTest, proxies, "INFO", "INFO", exploit = False, followRedirect = False)
    loc = res.headers.get('Location')

    if(res and loc != None and "/lfi/" in loc):
        # Full reflection + after the http|s protocol cases
        if(loc == "/lfi/a/../" or loc == "http:///lfi/a/../" or loc == "https:///lfi/a/../"):
            if(args.postreq and len(args.postreq) > 1): print(colors.green("[+]") + " Open redirect -> '" + u + "' -> HTTP POST -> '" + postTest.replace("/lfi/a/../", "evil.com") + "'")
            else: print(colors.green("[+]") + " Open redirect -> '" + u.replace("/lfi/a/../", "evil.com") + "'")
            stats["vulns"] += 1
            br = True

        # Reflection after the relative path
        elif(loc == "//lfi/a/../" or loc == "///lfi/a../"):
            if(args.postreq and len(args.postreq) > 1): 
                print(colors.green("[+]") + " Open redirect via relative double slash -> '" + u + "' -> HTTP POST -> '" + postTest.replace("/lfi/a/../", "/evil.com/") + "'")
            else: 
                print(colors.green("[+]") + " Open redirect via relative double slash -> '" + u.replace("/lfi/a/../", "/evil.com/") + "'")
            stats["vulns"] += 1
            br = True

        elif("/a/../" in loc):
            if(args.postreq and len(args.postreq) > 1):
                print(colors.green("[+]") + " Client-Side path traversal redirect -> '" + u + "' -> HTTP POST -> '" + postTest.replace("/lfi/a/../", "/../arbitrary/endpoint") + "'")
            else: 
                print(colors.green("[+]") + " Client-Side path traversal redirect -> '" + u.replace("/lfi/a/../", "/../arbitrary/endpoint") + "'")
            stats["vulns"] += 1
            br = True

    return