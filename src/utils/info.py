from src.utils import colors
from src.utils.arguments import args, logging

#Prints info about reverse shell attack to stdout
def printInfo(ip, port, shellType, attackMethod):
    logging.info(colors.green("[.]") + " Trying to pop reverse shell to {0}:{1} using {2} via {3}...".format(ip, port, shellType, attackMethod))
