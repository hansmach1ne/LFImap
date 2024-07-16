"""cleanup"""
import os

from src.utils.stats import print_stats


# Cleans up all temporary files created during testing
def lfimap_cleanup(webDir):
    """lfimap_cleanup"""
    if os.path.exists(f"{webDir}{os.path.sep}reverse_shell_lin_tmp.php"):
        os.remove(f"{webDir}{os.path.sep}reverse_shell_lin_tmp.php")
    if os.path.exists(f"{webDir}{os.path.sep}reverse_shell_win_tmp.php"):
        os.remove(f"{webDir}{os.path.sep}reverse_shell_win_tmp.php")

    # Print stats info
    print_stats()

    # Exit
    os._exit(0)
