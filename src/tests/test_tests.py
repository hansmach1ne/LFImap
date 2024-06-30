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
from src.utils.stats import stats
import src.utils.arguments
import src.attacks.rfi

# Event that shuts down the server when we are done with it
shut_down_http_server = threading.Event()

expecting_filename_rfi = [
    "ysvznc.php",
    "ysvznc.jsp",
    "ysvznc.html",
    "ysvznc.gif",
    "ysvznc.png",
]


class CustomHTTPRequestHandler(SimpleHTTPRequestHandler):
    """CustomHTTPRequestHandler"""

    def do_GET(self) -> None:
        """do_GET"""
        if self.path.startswith("/vulnerabilities") or self.path == "/":
            uri = urllib3.util.parse_url(self.path)
            response = b""
            if uri.query is not None:
                params = urllib.parse.parse_qs(uri.query)
                if "page" in params:
                    # Check if it is one of our markers
                    pages = params["page"]
                    found = False
                    for page in pages:
                        page = urllib.parse.unquote(page)
                        for filename in expecting_filename_rfi:
                            if page.endswith(f"/{filename}"):
                                response = base64.b64decode(
                                    "OTYxYmIwOGE5NWRiYzM0Mzk3MjQ4ZDkyMzUyZGE3OTk="
                                )
                                found = True
                                break
                        if found:
                            break

                    if not found:
                        for value in pages:
                            value = urllib.parse.unquote(value)
                            if "cat${IFS}/etc/passwd" in value:
                                response = b"root:x:0:0"
                                found = True
                                break

                            if "1&ipconfig /all&" in value:
                                response = b"Windows IP Configuration"
                                found = True
                                break

            self.send_response(200)
            self.end_headers()
            self.wfile.write(response)
        else:
            self.send_response(404)
            self.end_headers()


def dummy_http_server():
    """Dummy HTTP Server for testing"""
    server_address = ("127.0.0.1", 8080)
    http_handler = CustomHTTPRequestHandler
    # Prevent the HTTP Server from logging the requests into the stdout
    http_handler.log_message = lambda *args, **kwargs: None
    httpd = ThreadingHTTPServer(server_address, http_handler)

    while not shut_down_http_server.is_set():
        httpd.handle_request()


def custom_init_args():
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

def start_web_server():
    """ Start HTTP Server """
    shut_down_http_server.clear()
    thread = threading.Thread(target=dummy_http_server)
    thread.start()

    time.sleep(0.5)


def stop_web_server():
    """ Stop web server """
    shut_down_http_server.set()
    # Trigger another handle_request, so that the loop exits

    try:
        requests.get("http://127.0.0.1:8080/", timeout=1)
    except:
        pass


def test_test_rfi():
    """Test the test_rfi interface"""

    start_web_server()
    custom_init_args()

    src.attacks.rfi.test_rfi("http://127.0.0.1:8080/vulnerabilities/fi/?page=PWN", "")

    if stats["requests"] != 5:
        msg = f"We are expecting 5 'requests', got: {stats['requests']}"
        pytest.fail(msg)

    if stats["vulns"] != 5:
        msg = f"We are expecting 5 'vulns', got: {stats['vulns']}"
        pytest.fail(msg)

    print(f"{stats=}")

    stop_web_server()


def test_test_cmd_injection():
    """Test the test_cmd_injection interface"""

    start_web_server()
    custom_init_args()

    src.attacks.cmdi.test_cmd_injection(
        "http://127.0.0.1:8080/vulnerabilities/fi/?page=PWN", ""
    )

    if stats["requests"] != 2:
        msg = f"We are expecting 2 'requests', got: {stats['requests']}"
        pytest.fail(msg)

    if stats["vulns"] != 2:
        msg = f"We are expecting 2 'vulns', got: {stats['vulns']}"
        pytest.fail(msg)

    print(f"{stats=}")

    stop_web_server()