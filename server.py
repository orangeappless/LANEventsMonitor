#!/usr/bin/env python3


import sys
import argparse
import socket
import threading
import ssl


thread_count = 0        # Track number of threads/clients


def parse_args():
    # Parse command line args
    parser = argparse.ArgumentParser()

    parser.add_argument("-p",
                        "--port",
                        type=int,
                        help="Port that this application will listen on",
                        required=True)

    args = parser.parse_args()

    return args


def create_ssl_socket(socket):
    certfile = 'certs/domain.crt'
    keyfile = 'certs/domain.key'

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)

    secure_socket = context.wrap_socket(socket, server_side=True)
    # secure_socket.setblocking(0)

    return secure_socket


def handle_client(socket):
    global thread_count
    socket.send(str.encode(f"Connected to {socket.getsockname()}"))

    while True:
        try:
            data = socket.recv(4096)
        except:
            print("No data from client")

        if data:
            remote_client = socket.getpeername()[0]
            print(f'{remote_client} :: {data.decode("utf-8")}')

        if not data:
            thread_count -= 1
            print(f"{socket.getpeername()[0]} :: disconnected, {thread_count} current client(s)")
            break

        # socket.sendall(str.encode(response))

    socket.close()


def main():
    # Parse arguments
    args = parse_args()

    # Server setup
    socket_ = socket.socket()

    # Wrap socket in SSL wrapper
    secure_socket = create_ssl_socket(socket_)

    host = ""
    port = args.port
    global thread_count

    try:
        secure_socket.bind((host, port))
    except socket.error as e:
        print(str(e))
    
    secure_socket.listen()
    print(f"Listening on port {port}...")

    # Accept incoming connections
    while True:
        try:
            client, addr = secure_socket.accept()
            thread_count += 1
            print(f"{addr[0]} :: connected, {thread_count} current client(s)")
            threading.Thread(target=handle_client, args=(client, )).start()
        except KeyboardInterrupt:
            print("Keyboard interrupt")
            secure_socket.close()
            break

    secure_socket.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting program...")
        sys.exit()
