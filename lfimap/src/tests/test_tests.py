"""test_rfi_exploit"""
import time
import os
import threading
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
import base64
import urllib.parse
import urllib3.util

import requests
import pytest
import src.attacks.cmdi
from src.utils.stats import stats, init_stats
import src.utils.arguments
import src.attacks.rfi

# Event that shuts down the server when we are done with it
shut_down_http_server = threading.Event()


class CustomHTTPRequestHandler(SimpleHTTPRequestHandler):
    """CustomHTTPReq`uestHandler"""

    request_response_markers = []

    def do_GET(self) -> None:
        """do_GET"""
        if self.request_response_markers is None:
            print("WARNING: NO markers have been set")
            self.send_response(200)
            self.end_headers()

        if self.path.startswith("/vulnerabilities") or self.path == "/":
            uri = urllib3.util.parse_url(self.path)
            response = b""
            if uri.query is not None:
                params = urllib.parse.parse_qs(uri.query)
                if "name" in params:
                    # Check if it is one of our markers
                    values = params["name"]
                    found = False
                    for value in values:
                        value = urllib.parse.unquote(value)

                        for request_response_marker in self.request_response_markers:
                            for value in request_response_marker["find"]:
                                response = request_response_marker["respond"]
                                found = True
                                break

                            if found:
                                break

                        if found:
                            break

            self.send_response(200)
            self.end_headers()
            self.wfile.write(response)
        else:
            self.send_response(404)
            self.end_headers()


def dummy_http_server(request_response_markers):
    """Dummy HTTP Server for testing"""
    server_address = ("127.0.0.1", 8080)
    http_handler = CustomHTTPRequestHandler
    http_handler.request_response_markers = request_response_markers

    # Prevent the HTTP Server from logging the requests into the stdout
    http_handler.log_message = lambda *args, **kwargs: None
    httpd = ThreadingHTTPServer(server_address, http_handler)

    while not shut_down_http_server.is_set():
        httpd.handle_request()


def custom_init_args():
    """Custom Init of the Args"""
    src.utils.arguments.args = {
        "url": ["http://127.0.0.1:8080/vulnerabilities/fi/?page=PWN"],
        "f": None,
        "reqfile": None,
        "cookie": "",
        "postreq": False,
        "httpheaders": {
            "User-Agent": "Mozilla/3.01 (Macintosh; PPC)",
            "Accept": "*/*",
            "Connection": "Close",
        },
        "method": "GET",
        "proxyAddr": None,
        "agent": None,
        "referer": None,
        "param": "PWN",
        "delay": None,
        "maxTimeout": None,
        "http_valid": [200, 204, 301, 302, 303],
        "csrfParameter": None,
        "csrfMethod": None,
        "csrfUrl": None,
        "csrfData": None,
        "secondMethod": None,
        "checkUrl": None,
        "secondData": None,
        "force_ssl": False,
        "no_stop": True,
        "php_filter": False,
        "php_input": False,
        "php_data": False,
        "php_expect": False,
        "trunc": False,
        "rfi": False,
        "cmd": False,
        "file": False,
        "heuristics": False,
        "test_all": True,
        "encodings": None,
        "quick": False,
        "revshell": False,
        "lhost": None,
        "lport": None,
        "callback": None,
        "log": None,
        "verbose": True,
        "updateCsrfToken": False,
        "no_colors": False,
    }

    script_directory = os.path.dirname(
        __file__ + os.sep + ".." + os.sep + ".." + os.sep + ".." + os.sep
    )
    script_directory = os.path.abspath(script_directory)
    src.utils.arguments.args["script_directory"] = script_directory

    src.utils.arguments.args[
        "truncWordlist"
    ] = f"{src.utils.arguments.args['script_directory']}/src/wordlists/short.txt"


def start_web_server(request_response_markers=None):
    """Start HTTP Server"""
    shut_down_http_server.clear()
    thread = threading.Thread(target=dummy_http_server, args=[request_response_markers])
    thread.start()

    time.sleep(0.5)


def stop_web_server():
    """Stop web server"""
    shut_down_http_server.set()
    # Trigger another handle_request, so that the loop exits

    try:
        requests.get("http://127.0.0.1:8080/", timeout=1)
    except:
        pass


def test_test_rfi():
    """Test the test_rfi interface"""

    start_web_server(
        [
            {
                "find": [
                    "/ysvznc.php",
                    "/ysvznc.jsp",
                    "/ysvznc.html",
                    "/ysvznc.gif",
                    "/ysvznc.png",
                ],
                "respond": base64.b64decode(
                    "OTYxYmIwOGE5NWRiYzM0Mzk3MjQ4ZDkyMzUyZGE3OTk="
                ),
            }
        ],
    )
    custom_init_args()
    init_stats()

    src.attacks.rfi.test_rfi("http://127.0.0.1:8080/vulnerabilities/?name=PWN", "")

    stop_web_server()

    if stats["requests"] != 5:
        msg = f"We are expecting 5 'requests', got: {stats['requests']}"
        pytest.fail(msg)

    if stats["vulns"] != 5:
        msg = f"We are expecting 5 'vulns', got: {stats['vulns']}"
        pytest.fail(msg)

    print(f"{stats=}")


def test_test_cmd_injection():
    """Test the test_cmd_injection interface"""

    start_web_server(
        [
            {"find": ["cat${IFS}/etc/passwd"], "respond": b"root:x:0:0"},
            {"find": ["1&ipconfig /all&"], "respond": b"Windows IP Configuration"},
        ]
    )
    custom_init_args()
    init_stats()

    src.attacks.cmdi.test_cmd_injection(
        "http://127.0.0.1:8080/vulnerabilities/fi/?name=PWN", ""
    )

    stop_web_server()

    if stats["requests"] != 2:
        msg = f"We are expecting 2 'requests', got: {stats['requests']}"
        pytest.fail(msg)

    if stats["vulns"] != 2:
        msg = f"We are expecting 2 'vulns', got: {stats['vulns']}"
        pytest.fail(msg)

    print(f"{stats=}")
