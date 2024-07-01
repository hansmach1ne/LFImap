"""Info"""
from src.utils.colors import Colors


def printInfo(ip, port, shellType, attackMethod):
    """Prints info about reverse shell attack to stdout"""
    print(
        Colors().green("[.]")
        + f" Trying to pop reverse shell to {ip}:{port} using {shellType} via {attackMethod}...",
        flush = True
    )


def printFancyString(newString, lastPrintedStringLen):
    """Print fency string"""
    if len(newString) < lastPrintedStringLen:
        difference = lastPrintedStringLen - len(newString)
        print("\r" + newString + difference * " ", end="", flush = True)
    else:
        print("\r" + newString, end="", flush = True)

    return len(newString)
