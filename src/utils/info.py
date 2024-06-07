"""info module"""
from src.utils import colors


def printInfo(ip, port, shellType, attackMethod):
    """Prints info about reverse shell attack to stdout"""
    print(
        colors.green("[.]")
        + f" Trying to pop reverse shell to {ip}:{port} using {shellType} via {attackMethod}..."
    )
