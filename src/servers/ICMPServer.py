"""ICMP Server"""
import threading
import socket
from src.utils.colors import Colors
from src.utils.arguments import init_args


class ICMPThread(threading.Thread):
    """ICMP Thread"""
    def __init__(self):
        threading.Thread.__init__(self)
        self.result = None

    def run(self):
        args  = init_args()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
            self.result = False

            while True:
                data, _ = s.recvfrom(1024)
                if data:
                    self.result = True
        except PermissionError:
            if args['verbose']:
                print(
                    Colors().red("[-]")
                    + " Raw socket access is not allowed. For blind ICMP command injection test, rerun lfimap as admin/sudo with '-c'",
                    flush = True
                )

    def getResult(self):
        """getResult"""
        return self.result

    def setResult(self, boolean):
        """setResult"""
        self.result = boolean
