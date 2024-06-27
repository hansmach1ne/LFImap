"""HTTP Server"""
import http.client
import http.server
import socketserver
import src.utils.arguments
from src.configs import config
from src.utils import colors


class ServerHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP Server Handler"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=config.webDir, **kwargs)

    def log_message(self, format, *args):
        pass


def serve_forever():
    """Serve Forever"""
    socketserver.TCPServer.allow_reuse_address = True
    try:
        with socketserver.TCPServer(("", config.rfi_test_port), ServerHandler) as httpd:
            if src.utils.arguments.args.verbose:
                print(
                    colors.blue("[i]")
                    + " Opening temporary local web server on port "
                    + str(config.rfi_test_port)
                    + " and hosting $LFIMAP_DIR/src/exploits that will be used for test inclusion",
                    flush = True
                )
            try:
                httpd.serve_forever()
            except:
                httpd.server_close()
    except:
        if src.utils.arguments.args.verbose:
            print(
                colors.red("[-]")
                + " Cannot setup local web server on port "
                + str(config.rfi_test_port)
                + ", it's in use or unavailable...",
                flush = True
            )
