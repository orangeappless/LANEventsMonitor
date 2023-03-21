#!/usr/bin/env python3


import sys
import socket
import configparser
from multiprocessing import Process
from threading import Thread
import ssl

from modules import dir_watcher
from modules import user_watcher
from modules import root_watcher
from modules import ssh_watcher


def parse_config(config_file_path):
    config_parser = configparser.RawConfigParser()
    config_parser.read(config_file_path)
    
    return config_parser


def create_secure_socket(socket):
    certfile = 'certs/domain.crt'
    keyfile = 'certs/domain.key'

    secure_socket = ssl.wrap_socket(socket, keyfile, certfile)

    return secure_socket


def main():
    # Parse config file
    config_file = "config.ini"
    configs = parse_config(config_file)

    # Connect to server
    socket_ = socket.socket()
    secure_socket = create_secure_socket(socket_)

    server = str(dict(configs.items('CLIENT_CONF'))['server_ip'])
    port = int(dict(configs.items('CLIENT_CONF'))['server_port'])

    print("Connecting...")

    try:
        secure_socket.connect((server, port))
    except socket.error as e:
        print(str(e))
    
    # Confirm connection to server
    res = secure_socket.recv(4096)
    print(res.decode("utf-8"))

    # List to store processes for each monitoring module
    proc_list = []
    thread_list = []

    # Monitor target directories
    watcher_dirs = dict(configs.items("DIR_WATCHER"))
    # dir_watcher_proc = Process(
    #     target=dir_watcher.start_watcher,
    #     args=(watcher_dirs, secure_socket,)
    # )
    # proc_list.append(dir_watcher_proc)
    dir_watcher_thread = Thread(
        target=dir_watcher.start_watcher,
        args=(watcher_dirs, secure_socket)
    )
    thread_list.append(dir_watcher_thread)

    # # Monitor user account changes
    audit_log_file = dict(configs.items('USER_WATCHER'))['log']
    # user_watcher_proc = Process(
    #     target=user_watcher.start_user_watcher,
    #     args=(audit_log_file, secure_socket,)
    # )
    # proc_list.append(user_watcher_proc)
    user_watcher_thread = Thread(
        target=user_watcher.start_user_watcher,
        args=(audit_log_file, secure_socket)
    )
    thread_list.append(user_watcher_thread)

    # Monitor root/wheel logins
    root_log_file = dict(configs.items('ROOT_WATCHER'))['log']
    # root_watcher_proc = Process(
    #     target=root_watcher.start_root_watcher,
    #     args=(root_log_file, secure_socket,)
    # )
    # proc_list.append(root_watcher_proc)
    root_watcher_thread = Thread(
        target=root_watcher.start_root_watcher,
        args=(root_log_file, secure_socket)
    )
    thread_list.append(root_watcher_thread)
    
    # Monitor incoming SSH logins
    root_log_file = dict(configs.items('SSH_WATCHER'))['log']
    # ssh_watcher_proc = Process(
    #     target=ssh_watcher.start_ssh_watcher,
    #     args=(root_log_file, secure_socket, dict(configs.items('SSH_WATCHER'))['max_attempts'], dict(configs.items('SSH_WATCHER'))['block_time'])
    # )
    # proc_list.append(ssh_watcher_proc)
    ssh_watcher_thread = Thread(
        target=ssh_watcher.start_ssh_watcher,
        args=(root_log_file, secure_socket, dict(configs.items('SSH_WATCHER'))['max_attempts'], dict(configs.items('SSH_WATCHER'))['block_time'])
    )
    thread_list.append(ssh_watcher_thread)

    # Start all watchers
    # for proc in proc_list:
    #     proc.start()
    for thread in thread_list:
        thread.start()

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
