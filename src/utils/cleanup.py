import os

from src.utils.stats import printStats

#Cleans up all temporary files created during testing
def lfimap_cleanup(webDir, statistics):
    if(os.path.exists(webDir + os.path.sep + "reverse_shell_lin_tmp.php")):
        os.remove(webDir + os.path.sep + "reverse_shell_lin_tmp.php")
    if(os.path.exists(webDir + os.path.sep + "reverse_shell_win_tmp.php")):
        os.remove(webDir + os.path.sep + "reverse_shell_win_tmp.php")

    #Print stats info
    printStats()

    #Exit
    os._exit(0)