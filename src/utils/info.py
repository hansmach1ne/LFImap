from src.utils import colors

#Prints info about reverse shell attack to stdout
def printInfo(ip, port, shellType, attackMethod):
    print(colors.green("[.]") + " Trying to pop reverse shell to {0}:{1} using {2} via {3}...".format(ip, port, shellType, attackMethod))
