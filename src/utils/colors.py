def green(text):
    GREEN = '\033[92m'
    RESET = '\033[0m'
    return GREEN + text + RESET
    
def red(text):
    RED = '\033[91m'
    RESET = '\033[0m'
    return RED + text + RESET

def blue(text):
    BLUE = '\033[94m'
    RESET = '\033[0m'
    return BLUE + text + RESET

def yellow(text):
    YELLOW = '\033[93m'
    RESET = '\033[0m'
    return YELLOW + text + RESET

def purple(text):
    ORANGE = '\033[95m'
    RESET = '\033[0m'
    return ORANGE + text + RESET

def lightblue(text):
    LIGHTBLUE = '\033[1;36m'
    RESET = '\033[0m'
    return LIGHTBLUE + text + RESET