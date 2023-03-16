#!/usr/bin/env python3


import sys
import argparse
import socket
import threading


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


def handle_client(socket):
    global thread_count
    socket.send(str.encode(f"Connected to {socket.getsockname()}"))

    while True:
        try:
            data = socket.recv(4096)
        except:
            print("No data from client")

        print(data.decode("utf-8"))

        response = "Server echo: " + data.decode("utf-8")

        if not data:
            print(f"[Disconnected] {socket.getpeername()[0]}: {str(socket.getpeername()[1])}")
            thread_count -= 1
            print(f"Number of threads/clients: {str(thread_count)}")
            break

        # socket.sendall(str.encode(response))

    socket.close()


def main():
    # Parse arguments
    args = parse_args()

    # Server setup
    socket_ = socket.socket()
    host = ""
    port = args.port
    global thread_count

    try:
        socket_.bind((host, port))
    except socket.error as e:
        print(str(e))
    
    socket_.listen()
    print(f"Listening on port {port}...")

    # Accept incoming connections
    while True:
        try:
            client, addr = socket_.accept()
            print(f"[Connected] {addr[0]}: {str(addr[1])}")

            threading.Thread(target=handle_client, args=(client, )).start()
            thread_count += 1
            print(f"Number of threads/clients: {str(thread_count)}")
        except:
            print("Keyboard interrupt")
            socket_.close()
            break

    socket_.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting program...")
        sys.exit()
