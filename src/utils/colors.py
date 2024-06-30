"""colors"""
import os

from src.utils.arguments import init_args

class Colors():
    def __init__(self) -> None:
        self.args = init_args()

    def green(self, text):
        """green"""
        if self.args["no_colors"]:
            return text

        if os.name == "nt":
            os.system("")

        GREEN = "\033[92m"
        RESET = "\033[0m"
        return GREEN + text + RESET


    def red(self, text):
        """red"""
        if self.args["no_colors"]:
            return text

        if os.name == "nt":
            os.system("")

        RED = "\033[91m"
        RESET = "\033[0m"

        return RED + text + RESET


    def blue(self, text):
        """blue"""
        if self.args["no_colors"]:
            return text

        if os.name == "nt":
            os.system("")

        BLUE = "\033[94m"
        RESET = "\033[0m"

        return BLUE + text + RESET


    def yellow(self, text):
        """yellow"""
        if self.args["no_colors"]:
            return text

        if os.name == "nt":
            os.system("")

        YELLOW = "\033[93m"
        RESET = "\033[0m"

        return YELLOW + text + RESET


    def purple(self, text):
        """purple"""
        if self.args["no_colors"]:
            return text

        ORANGE = "\033[95m"
        RESET = "\033[0m"

        return ORANGE + text + RESET


    def lightblue(self, text):
        """lightblue"""
        if self.args["no_colors"]:
            return text

        if os.name == "nt":
            os.system("")

        LIGHTBLUE = "\033[1;36m"
        RESET = "\033[0m"

        return LIGHTBLUE + text + RESET
