#!/usr/bin/env python3


import sys
import socket
import configparser
from multiprocessing import Process

from modules import dir_watcher
from modules import user_watcher
from modules import root_watcher


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

    # List to store processes for each monitoring module
    proc_list = []

    # Monitor target directories
    watcher_dirs = dict(configs.items("DIR_WATCHER"))
    dir_watcher_proc = Process(
        target=dir_watcher.start_watcher,
        args=(watcher_dirs, socket_,)
    )
    proc_list.append(dir_watcher_proc)

    # # Monitor user account changes
    audit_log_file = dict(configs.items('USER_WATCHER'))['log']
    user_watcher_proc = Process(
        target=user_watcher.start_user_watcher,
        args=(audit_log_file, socket_,)
    )
    proc_list.append(user_watcher_proc)

    # Monitor root/wheel logins
    root_log_file = dict(configs.items('ROOT_WATCHER'))['log']
    root_watcher_proc = Process(
        target=root_watcher.start_root_watcher,
        args=(root_log_file, socket_,)
    )
    proc_list.append(root_watcher_proc)
    
    # Start all watchers
    for proc in proc_list:
        proc.start()

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
