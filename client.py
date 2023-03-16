#!/usr/bin/env python3


import sys
import socket
import configparser
from multiprocessing import Process

from modules import dir_watcher
from modules import user_watcher


def parse_config(config_file_path):
    config_parser = configparser.RawConfigParser()
    config_parser.read(config_file_path)
    
    return config_parser


def main():
    # Parse config file
    config_file = "config.ini"
    configs = parse_config(config_file)

    # Connect to server
    socket_ = socket.socket()
    server = str(dict(configs.items('CLIENT_CONF'))['server_ip'])
    port = int(dict(configs.items('CLIENT_CONF'))['server_port'])

    print("Connecting...")

    try:
        socket_.connect((server, port))
    except socket.error as e:
        print(str(e))
    
    # Confirm connection to server
    res = socket_.recv(4096)
    print(res.decode("utf-8"))

    # Add watcher for each directory listed in config file
    watcher_dirs = dict(configs.items("WATCHER_DIRS"))
    dir_watcher.start_watcher(watcher_dirs, socket_)

    # Monitor user files
    audit_log_file = dict(configs.items('USER_FILES'))['audit_log']
    user_watcher.start_user_watcher(audit_log_file, socket_)

    

    # while True:
    #     data = input("> ")
    #     socket_.send(str.encode(data))
    
    #     res = socket_.recv(4096)
    #     print(res.decode("utf-8"))

    # socket_.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting program...")
        sys.exit()
