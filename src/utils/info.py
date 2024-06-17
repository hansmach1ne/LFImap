from src.utils import colors
from src.configs import config

#Prints info about reverse shell attack to stdout
def printInfo(ip, port, shellType, attackMethod):
    print(colors.green("[.]") + " Trying to pop reverse shell to {0}:{1} using {2} via {3}...".format(ip, port, shellType, attackMethod))

def printFancyString(newString, lastPrintedStringLen):
    if(len(newString) < lastPrintedStringLen):
        difference = lastPrintedStringLen - len(newString)
        print("\r" + newString + difference * " ", end='', flush=True)
    else: print("\r" + newString, end='', flush=True)
    return len(newString)
