#!/usr/bin/env python3


import sys
import argparse
import socket


def parse_args():
    # Parse command line args
    parser = argparse.ArgumentParser()

    parser.add_argument("-s",
                        "--server",
                        type=str,
                        help="IP of remote server",
                        required=True)

    parser.add_argument("-p",
                        "--port",
                        type=int,
                        help="Port of remote server",
                        required=True)

    args = parser.parse_args()

    return args


def main():
    # Get command line args
    args = parse_args()

    # Connect to server
    socket_ = socket.socket()
    server = args.server
    port = args.port

    print("Connecting...")

    try:
        socket_.connect((server, port))
    except socket.error as e:
        print(str(e))
    
    # Confirm connection to server
    res = socket_.recv(4096)
    print(res.decode("utf-8"))

    while True:
        data = input("> ")
        socket_.send(str.encode(data))
    
        res = socket_.recv(4096)
        print(res.decode("utf-8"))

    socket_.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting program...")
        sys.exit()
