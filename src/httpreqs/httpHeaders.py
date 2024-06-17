"""HTTP Headers"""
import random
from src.utils.arguments import args


def addHeader(headers, newKey, newVal):
    """"Add a header to the dict"""
    headers[newKey] = newVal
    return headers


def delHeader(headers, key):
    """Remove header from the dict"""
    headers.pop(key)
    return headers


def initHttpHeaders():
    """Init the header dict"""
    headers = {}
    user_agents = []
    with open("user-agents.txt", "r", encoding="latin1") as file_handle:
        user_agents_data = file_handle.readlines()

        for line in user_agents_data:
            if line.startswith("#"):
                continue

            user_agents.append(line)

    if args.agent:
        headers["User-Agent"] = args.agent
    else:
        headers["User-Agent"] = random.choice(user_agents)
    if args.referer:
        headers["Referer"] = args.referer

    headers["Accept"] = "*/*"
    headers["Connection"] = "Close"

    return headers
