#!/usr/bin/env python3


import sys
import socket
import configparser
from threading import Thread
import ssl

from modules import dir_watcher
from modules import user_watcher
from modules import root_watcher
from modules import ssh_watcher
from modules import firewalld_watcher


def parse_config(config_file_path):
    config_parser = configparser.RawConfigParser()
    config_parser.read(config_file_path)
    
    return config_parser


def init_threat_file(threat_file):
    with open(f'utilities/{threat_file}', 'r+') as file:
        file.seek(0)
        file.write(str(0) + '\n')
        file.truncate()


def create_secure_socket(socket):
    certfile = 'certs/domain.crt'
    keyfile = 'certs/domain.key'

    secure_socket = ssl.wrap_socket(socket, keyfile, certfile)

    return secure_socket


def main():
    # Parse config file
    config_file = "config.ini"
    configs = parse_config(config_file)

    # Reinitialize threat file on each startup; sets current threat of client to 0
    threat_file = dict(configs.items('THREAT_MGMT'))['threat_file']     # File which stores client's current threat level
    init_threat_file(threat_file)

    # Set threat levels
    threat_levels_config = dict(configs.items('THREAT_LEVELS'))
    max_threat = int(threat_levels_config['max_threat'])
    mid_threat = int(threat_levels_config['mid_threat'])
    default_threat = int(threat_levels_config['default_threat'])

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
    thread_list = []

    # Monitor target directories
    watcher_dirs = dict(configs.items("DIR_WATCHER"))
    dir_watcher_thread = Thread(
        target=dir_watcher.start_watcher,
        args=(watcher_dirs, secure_socket, threat_file, max_threat, mid_threat, default_threat)
    )
    thread_list.append(dir_watcher_thread)

    # Monitor user account changes
    user_watcher_configs = dict(configs.items('USER_WATCHER'))
    user_watcher_audit = user_watcher_configs['log']
    user_watcher_thread = Thread(
        target=user_watcher.start_user_watcher,
        args=(user_watcher_audit, secure_socket, user_watcher_configs['block_time'], threat_file, max_threat, mid_threat, default_threat)
    )
    thread_list.append(user_watcher_thread)

    # Monitor root/wheel logins
    root_watcher_configs = dict(configs.items('ROOT_WATCHER'))
    root_watcher_audit = root_watcher_configs['log']
    root_watcher_thread = Thread(
        target=root_watcher.start_root_watcher,
        args=(root_watcher_audit, secure_socket, root_watcher_configs['block_time'], threat_file, max_threat, mid_threat, default_threat)
    )
    thread_list.append(root_watcher_thread)
    
    # Monitor incoming SSH logins
    ssh_watcher_configs = dict(configs.items('SSH_WATCHER'))
    ssh_watcher_audit = ssh_watcher_configs['log']
    ssh_watcher_thread = Thread(
        target=ssh_watcher.start_ssh_watcher,
        args=(ssh_watcher_audit, secure_socket, ssh_watcher_configs['block_time'], threat_file, max_threat, mid_threat, default_threat)
    )
    thread_list.append(ssh_watcher_thread)

    # Monitor changes to firewalld
    firewalld_watcher_configs = dict(configs.items('FIREWALLD_WATCHER'))
    firewalld_watcher_audit = firewalld_watcher_configs['log']
    unallowed_services = firewalld_watcher_configs['unallowed_services'].split(',')
    unallowed_ports = firewalld_watcher_configs['unallowed_ports'].split(',')
    firewalld_watcher_thread = Thread(
        target=firewalld_watcher.start_firewalld_watcher,
        args=(firewalld_watcher_audit, secure_socket, threat_file, unallowed_services, unallowed_ports, max_threat, mid_threat, default_threat)
    )
    thread_list.append(firewalld_watcher_thread)

    # Start all watchers
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
