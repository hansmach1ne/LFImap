#!/usr/bin/env python3

import sys

from urllib3.exceptions import NewConnectionError
from requests.exceptions import ConnectTimeout
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Import configurations
from src.configs import config

# Import utilities
from src.servers.HTTPServer import ServerHandler
from src.servers.ICMPServer import ICMPThread
from src.utils.encodings import encode
from src.utils.arguments import args
from src.utils.args_check import checkArgs
from src.utils.cleanup import lfimap_cleanup
from src.utils.stats import stats

# Import custom request functionality
from src.httpreqs.request import prepareRequest
from src.httpreqs.request import REQUEST

# Disable/Mute TLS errors
from requests.packages.urllib3 import disable_warnings
disable_warnings(InsecureRequestWarning)

# Import attack modules
from src.attacks.heur import test_heuristics
from src.attacks.filter import test_filter
from src.attacks.input import test_input
from src.attacks.data import test_data
from src.attacks.expect import test_expect
from src.attacks.rfi import test_rfi
from src.attacks.cmdi import test_cmd_injection
from src.attacks.file import test_file_trunc
from src.attacks.trunc import test_trunc
from src.utils import colors
from src.utils.parseurl import get_all_params
from src.utils.parseurl import get_params_with_param
from src.utils.parseurl import post_params_with_param
from src.utils.parseurl import parse_url_parameters
from src.utils.parseurl import getHeadersToTest
from src.utils.parseurl import compare_dicts
from src.utils.parseurl import is_valid_url

from urllib.parse import parse_qs, urlsplit

def main():
    config.proxies['http'] = args.proxyAddr
    config.proxies['https'] = args.proxyAddr

    # If multiple URLS are specified from a file
    if(args.f):

        for iteration, url in enumerate(config.parsedUrls):
            if(not args.postreq or "".join(args.postreq[0]) == ""):
                args.postreq = [""]

                # Just in case check if URL is correctly formatted, it should be always correct up to this point, though...
                if(not is_valid_url(url)): 
                    print("URL: " + url + " is not valid. Skipping...")
                    continue

                print("\n" + colors.lightblue("[i]") + " Parsing URL [" + str(iteration+1) + "/" + str(len(config.parsedUrls)) + "]: '" + url + "'")
                    
            try:
                #Check if url is accessible
                tempUrl, headers, postTest = prepareRequest(args.param, "test", url, "")
                try:
                    r,_ = REQUEST(tempUrl, headers, postTest, config.proxies, "test", "test")
                    okCode = False

                    # In case expection has occurred and not caught
                    if(r == False):
                        continue

                    if(args.http_valid):
                        for http_code in args.http_valid:
                            if(http_code == r.status_code):
                                okCode = True

                        if(not okCode):
                            print(colors.red("[-] ") + " URL '" + tempUrl + "' is not accessible. HTTP code " + str(r.status_code) + ".")
                            print(colors.blue("[i]") + " Try specifying parameter --http-ok " + str(r.status_code) + "\n")
                            continue
                    else:
                        if(r.status_code != 200 and r.status_code != 204):
                            print(colors.red("[-]") + " URL '" + tempUrl + "' is not accessible. HTTP code " + str(r.status_code) + ". Skipping...")
                            print(colors.blue("[i]") + " Try specifying parameter --http-ok " + str(r.status_code) + "\n")
                            continue
                except:
                    print(colors.red("[-]") + " Exception occurred while accessing '" + tempUrl + "'. Skipping...")
                    raise
                    continue

 

                relativeVulnCount = stats["vulns"]
                stats["urls"] += 1

                if(not args.postreq or "".join(args.postreq[0]) == ""):
                    if(not args.verbose): print("")
                    print(colors.yellow("[i]") + " Preparing to test GET '" + get_params_with_param(url) + "' parameter...")

                #Perform all tests
                if(args.test_all):
                    test_heuristics(url, "")
                    test_filter(url, "")
                    test_input(url, "")
                    test_data(url, "")
                    test_expect(url, "")
                    test_rfi(url, "")
                    test_file_trunc(url, "")
                    test_trunc(url, "")
                    test_cmd_injection(url, "")

                    if(stats["vulns"] == relativeVulnCount):
                        print(colors.red("[-]") + " GET parameter '" + get_params_with_param(url) + "' doesn't seem to be vulnerable.\n") 
                    continue

                default = True

                if(args.heuristics):
                    default = False
                    test_heuristics(url, "")
                if(args.php_filter):
                    default = False
                    test_filter(url, "")
                if(args.php_input):
                    default = False
                    test_input(url, "")
                if(args.php_data):
                    default = False
                    test_data(url, "")
                if(args.php_expect):
                    default = False
                    test_expect(url, "")
                if(args.rfi):
                    default = False
                    test_rfi(url, "")
                if(args.file):
                    default = False
                    test_file_trunc(url, "")
                if(args.trunc):
                    default = False
                    test_trunc(url, "")
                if(args.cmd):
                    default=False
                    test_cmd_injection(url, "")
            
                #Default behaviour
                if(default):
                    test_filter(url, "")
                    test_input(url, "")
                    test_data(url, "")
                    test_expect(url, "")
                    test_rfi(url, "")
                    test_file_trunc(url, "")
                    test_trunc(url, "")
                
                if(stats["vulns"] == relativeVulnCount):
                    print(colors.red("[-]") + " GET parameter '" + get_params_with_param(url, args.param) + "' doesn't seem to be vulnerable.\n") 

            except ConnectTimeout:
                print(colors.red("[-]") + " URL '" + url + "' timed out. Skipping...")
            except ConnectionRefusedError:
                print(colors.red("[-]") + " Failed to establish connection to " + url)
            except NewConnectionError:
                print(colors.red("[-]") + " Failed to establish connection to " + url)
            except OSError:
                print(colors.red("[-]") + " Failed to establish connection to " + url)
            except KeyboardInterrupt:
                print("\nKeyboard interrupt detected. Exiting...")
                lfimap_cleanup(config.webDir, stats)
            except:
                raise

        lfimap_cleanup(config.webDir, stats)

    # If single URL is specified
    else:
        # for DEBUG purposes
        #print("Prepared: ")
        #print(args.url)
        #print(args.httpheaders)
        #if(args.postreq): print(args.postreq)

        #print("\nOriginal, stored inside config")
        #print(config.url)
        #if(config.postreq): print(config.postreq)

        turls = [] # list of strings
        tposts = [] # list of strings
        theaders = [] # list of dicts

        # Find out where the args.param are located at
        if(args.param in config.url): pwnInGetExists = True
        else: pwnInGetExists = False

        if(config.postreq and args.param in config.postreq): pwnInPostExists = True
        else: pwnInPostExists = False

        found_in_headkeys = args.param in args.httpheaders.keys()
        found_in_headvalues = args.param in (str(value) for value in args.httpheaders.values())

        if found_in_headkeys or found_in_headvalues: pwnInHeadersExists = True
        else: pwnInHeadersExists = False

        # Test header
        if(pwnInHeadersExists):
            tempUrl, headers, postTest = prepareRequest(args.param, args.param, config.url, config.postreq)
            turls.append(tempUrl)
            theaders.append(headers)
            tposts.append(postTest)
        else:
            if(pwnInGetExists or not pwnInPostExists and args.param in args.url[0]):
                # If the PWN is not in the url, parse all of the parameters
                if(args.param not in config.url):
                    for iteration, url in enumerate(args.url):
                        tempUrl, headers, postTest = prepareRequest(args.param, args.param, url, config.postreq)
                        turls.append(tempUrl)
                        theaders.append(headers)
                        tposts.append(postTest)

                # Parse only parameters that have PWN keyword
                else:
                    pwnInGetExists = True
                    tempUrl, headers, postTest = prepareRequest(args.param, args.param, config.url, config.postreq)
                    turls.append(tempUrl)
                    theaders.append(headers)
                    tposts.append(postTest)

            if(not pwnInGetExists and not pwnInHeadersExists):
                # If the PWN keyword is in the FORM-data line
                if(config.postreq and args.param not in config.postreq):
                    for i, post in enumerate(args.postreq):
                        tempUrl, headers, postTest = prepareRequest(args.param, args.param, config.url, post)
                        turls.append(tempUrl)
                        theaders.append(headers)
                        tposts.append(postTest)
                elif(config.postreq != None):
                    tempUrl, headers, postTest = prepareRequest(args.param, args.param, config.url, config.postreq)
                    turls.append(tempUrl)
                    theaders.append(headers)
                    tposts.append(postTest)
        
        # Test request to see if the site is accessible
        r,_ = REQUEST(tempUrl, headers, postTest, config.proxies, "test", "test")
        if(r == False):
            lfimap_cleanup(config.webDir, stats)

        okCode = False
        if(args.http_valid):
            for http_code in args.http_valid:
                if(http_code == r.status_code):
                    okCode = True

            if(not okCode):
                print(colors.red("[-] ") + tempUrl + " is not accessible. HTTP code " + str(r.status_code) + ".")
                print(colors.blue("[i]") + " Try specifying parameter --http-ok " + str(r.status_code) + "\n")
                sys.exit(-1)

        else:
            if(r.status_code != 200 and r.status_code != 204):
                print(colors.red("[-]") + tempUrl + " is not accessible. HTTP code " + str(r.status_code) + ". Exiting...")
                print(colors.blue("[i]") + " Try specifying parameter --http-ok " + str(r.status_code) + "\n")
                sys.exit(-1)

        # Main loop that will perform testing
        for iteration, url in enumerate(turls):
            post = tposts[iteration]
            headers = theaders[iteration]

            if(pwnInHeadersExists):
                # Handle plural
                if("," in getHeadersToTest(headers)): print("\n" + colors.yellow("[i]") + " Preparing to test headers '" + getHeadersToTest(headers) + "'")
                else: print("\n" + colors.yellow("[i]") + " Preparing to test header '" + getHeadersToTest(headers) + "'") 
                
            if(args.param in url):
                print("\n" + colors.yellow("[i]") + " Preparing to test GET '" + get_params_with_param(url) + "' parameter...")
                args.is_tested_param_post = False # Needed to handle -i

            if(args.postreq and args.param in post): 
                print("\n" + colors.yellow("[i]") + " Preparing to test form-line '" + post_params_with_param(post) + "' parameter...")
                args.is_tested_param_post = True # Needed to handle -i

            relativeVulnCount = stats["vulns"]
            stats["urls"] += 1

            #Perform all tests
            if(args.test_all):
                test_heuristics(url, post)
                test_filter(url, post)
                test_input(url, post)
                test_data(url, post)
                test_expect(url, post)
                test_file_trunc(url, post)
                test_rfi(url, post)
                test_trunc(url, post)
                test_cmd_injection(url, post)

                if(stats["vulns"] == relativeVulnCount and pwnInHeadersExists):
                    # Handle plural
                    if("," in getHeadersToTest(headers)): print(colors.red("[-]") + " Headers '" + getHeadersToTest(headers) + "' doesn't seem to be vulnerable.")
                    else: print(colors.red("[-]") + " Header '" + getHeadersToTest(headers) + "' doesn't seem to be vulnerable.") 

                if(stats["vulns"] == relativeVulnCount):
                    if(args.param in url):
                        print(colors.red("[-]") + " GET parameter '" + get_params_with_param(url) + "' doesn't seem to be vulnerable....")
                    if(args.postreq and args.param in post): 
                        print(colors.red("[-]") + " Form-line parameter '" + post_params_with_param(post) + "' doesn't seem to be vulnerable....")
                continue

            default = True

            if(args.heuristics):
                default = False
                test_heuristics(url, post)
            if(args.php_filter):
                default = False
                test_filter(url, post)
            if(args.php_input):
                default = False
                test_input(url, post)
            if(args.php_data):
                default = False
                test_data(url, post)
            if(args.php_expect):
                default = False
                test_expect(url, post)
            if(args.file):
                default = False
                test_file_trunc(url, post)
            if(args.rfi):
                default = False
                test_rfi(url, post)
            if(args.trunc):
                default = False
                test_trunc(url, post)
            if(args.cmd):
                default=False
                test_cmd_injection(url, post)

            #Default behaviour
            if(default):
                test_filter(url, post)
                test_input(url, post)
                test_data(url, post)
                test_expect(url, post)
                test_file_trunc(url, post)
                test_rfi(url, post)
                test_trunc(url, post)

            if(stats["vulns"] == relativeVulnCount and pwnInHeadersExists):
                # Handle plural
                if("," in getHeadersToTest(headers)): print(colors.blue("[i]") + " Headers '" + getHeadersToTest(headers) + "' doesn't seem to be vulnerable.")
                else: print(colors.blue("[i]") + " Header '" + getHeadersToTest(headers) + "' doesn't seem to be vulnerable.") 

            if(stats["vulns"] == relativeVulnCount):
                if(args.param in url):
                    print(colors.red("[-]") + " GET parameter '" + get_params_with_param(url) + "' doesn't seem to be vulnerable....")
                if(args.postreq and args.param in post): 
                    print(colors.red("[-]") + " Form-line parameter '" + post_params_with_param(post) + "' doesn't seem to be vulnerable....")

        lfimap_cleanup(config.webDir, stats)


if(__name__ == "__main__"):

    # Check command-line arguments
    if(not checkArgs()): sys.exit(-1)

    main()
