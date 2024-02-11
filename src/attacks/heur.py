import urllib.parse as urlparse
from src.utils.arguments import args
from src.configs.config import *
from src.httpreqs.request import prepareRequest
from src.httpreqs.request import REQUEST
from src.utils.stats import stats
from src.utils import colors
import re
import random
import string

def test_heuristics(url, post):
    br = False
    o = urlparse.urlparse(url)

    if(args.verbose):
        print("\n" + colors.blue("[i]") + " Testing misc issues using heuristics...")

    tests = []

    alphanumeric_chars = string.ascii_letters + string.digits

    rProtocol = ''.join(random.choice(alphanumeric_chars.lower()) for _ in range(3))
    rNumb1 = str(random.randint(1, 100))
    rLetter1 = random.choice(alphanumeric_chars.lower())
    rLetter2 = random.choice(alphanumeric_chars.lower())
    rLetter3 = ''.join(random.choice(string.ascii_letters.lower()) for _ in range(2))
    rNumb2 = str(random.randint(1, 100))
    rLetter4 = ''.join(random.choice(string.ascii_letters.lower()) for _ in range(2))

    # Custom XSS polyglot
    xssTest = rProtocol + "%3A" + rNumb1 + rLetter1 + "%3E" + rLetter2 + "%3C" + rLetter3 + "%3B" + rNumb2 + "%22%27" + rLetter4
    tests.append(xssTest)

    # Custom CRLF polyglot
    tests.append("%0d%0aLfi:13CRLF37%250d%250aLfi%3A13CRLF37%25%30D%25%30ALfi%3A13CRLF37")
    
    #TODO store these in a separate file and make it bigger
    fiErrors = ["warning", "include(", "require(", "fopen(", "fpassthru(", "readfile(", "fread(", "fgets("]
    sqlErrors = ["you have an error in your sql syntax", "unclosed qutation mark after the character string",
            "you have an error in your sql syntax", "mysql_query(", "mysql_fetch_array(", 
            "mysql_fetch_assoc(", "mysql_fetch_field(", "mysql_fetch_field_direct(", "mysql_fetch_lengths(", 
            "mysql_fetch_object(", "mysql_fetch_row(", "mysql_fetch_all(", "mysql_prepare(", "mysql_info(",
            "mysql_real_query(", "mysql_stmt_init(", "mysql_stmt_execute("]
    
    for test in tests:
        if(args.verbose and xssTest in test): print(colors.blue("[i]") + " Testing for XSS...")
        if(args.verbose and "%0d%0a" in test): print(colors.blue("[i]") + " Testing for CRLF...")

        vuln = False
        u, tempHeaders, postTest = prepareRequest(args.param, test, url, post)
        res, _ = REQUEST(u, tempHeaders, postTest, proxies, "INFO", "INFO")

        # HREF
        if(res and rProtocol+":" in res.text.lower()):
            pattern = r'href="' + rProtocol + '\\:[^"]*'
            matches = re.findall(pattern, res.text.lower())
            if(len(matches) > 0 and vuln == False):
                print("    Positive regex match found in response: " + pattern)
                vuln = True
                if(args.postreq and len(args.postreq) > 1): print(colors.green("[+]") + " XSS -> '" + u + "' -> HTTP POST -> '" + postTest + "' -> reflection in HREF attribute value")
                else: print(colors.green("[+]") + " XSS -> '" + u + "' -> reflection in HREF atribute value")

        if(res and rProtocol + ":" + rNumb1 + rLetter1 + ">" + rLetter2 + "<" + rLetter3 + ";" + rNumb2 + "\"'" + rLetter4 in res.text.lower()):
            vuln = True
            if(args.postreq and len(args.postreq) > 1): print(colors.green("[+]") + " XSS -> '" + u + "' -> HTTP POST -> '" + postTest + "' -> full reflection in response")
            else: print(colors.green("[+]") + " XSS -> '" + u + "' -> full reflection in response")

        else:
            # HREF
            if(res and rProtocol+":" in res.text.lower()):
                pattern = r'href="' + rProtocol + '\\:[^"]*'
                matches = re.findall(pattern, res.text.lower())
                if(len(matches) > 0 and vuln == False):
                    print("    Positive regex match found in response: " + pattern)
                    vuln = True
                    if(args.postreq and len(args.postreq) > 1): print(colors.green("[+]") + " XSS -> '" + u + "' -> HTTP POST -> '" + postTest + "' -> reflection in HREF attribute value. Check if javascript: is allowed")
                    else: print(colors.green("[+]") + " XSS -> '" + u + "' -> reflection in HREF atribute value. Check if javascript: is allowed")

            # ATTRIBUTE
            if(res and rNumb2 + "\"'" + rLetter4 in res.text.lower()):
                pattern = r'<[^>]+?\s*=\s*["\'][^"\']*?\b.*' + rNumb2 + '"\'' + rLetter4 + '\\b[^"\']*?["\'][^>]*>'
                matches = re.findall(pattern, res.text.lower())
                if(len(matches) > 0 and vuln == False):
                    print("    Positive regex match found in response: " + pattern)
                    vuln = True
                    if(args.postreq and len(args.postreq) > 1): print(colors.green("[+]") + " XSS -> '" + u + "' -> HTTP POST -> '" + postTest + "' -> reflection in tag attribute")
                    else: print(colors.green("[+]") + " XSS -> '" + u + "' -> reflection in tag atribute")

            #SCRIPT
            if(res and rLetter3 + ";" + rNumb2 in res.text.lower()):
                pattern = r''+ rLetter3 + ";" + rNumb2 + '["\'"][\\s\\S]*\\<\\/script\\>'
                compiled_pattern = re.compile(pattern)

                matches = re.findall(pattern, res.text.lower())
                if(len(matches) > 0 and vuln == False):
                    print("    Positive regex match found in response: " + pattern)
                    vuln = True
                    if(args.postreq and len(args.postreq) > 1): print(colors.green("[+]") + " XSS -> '" + u + "' -> HTTP POST -> '" + postTest + "' -> reflection in script context")
                    else: print(colors.green("[+]") + " XSS -> '" + u + "' -> reflection in script context")
        
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

        if(args.quick or br): break

    if(args.verbose): print(colors.blue("[i]") + " Testing for error-based info leak...")

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
    if(args.verbose): print(colors.blue("[i]") + " Testing for open redirect...")

    u, tempHeaders, postTest = prepareRequest(args.param, "/lfi/a/../", url, post)
    # followRedirect must be False, otherwise if CSRF token refresh needs to happen, it might not be able to refresh the token and break
    res, _ = REQUEST(u, tempHeaders, postTest, proxies, "INFO", "INFO", exploit = False)

    if(res and "Location" in res.headers):
        loc = res.headers.get('Location')
    else: loc = None

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

        elif("/a/../" in loc and "/a/../" in urlparse.urlparse(loc).path):
            if(args.postreq and len(args.postreq) > 1):
                print(colors.green("[+]") + " Client-Side path traversal redirect -> '" + u + "' -> HTTP POST -> '" + postTest.replace("/lfi/a/../", "/../arbitrary/endpoint") + "'")
            else: 
                print(colors.green("[+]") + " Client-Side path traversal redirect -> '" + u.replace("/lfi/a/../", "/../arbitrary/endpoint") + "'")
            stats["vulns"] += 1
            br = True
    return