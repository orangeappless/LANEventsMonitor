#!/usr/bin/env python3


import sys, os
import socket
import configparser
from threading import Thread
import ssl
import subprocess
from pathlib import Path
import time

from modules import dir_watcher
from modules import user_watcher
from modules import root_watcher
from modules import ssh_watcher
from modules import firewalld_watcher
from modules import cmd_watcher


def parse_config(config_file_path):
    config_parser = configparser.RawConfigParser()
    config_parser.read(config_file_path)
    
    return config_parser


def init_threat_file(threat_file):
    filename = Path(f'utilities/{threat_file}')
    filename.touch(exist_ok=True)

    with open(f'utilities/{threat_file}', 'r+') as file:
        file.seek(0)
        file.write(str(0) + '\n')
        file.truncate()


def remove_auditd_rules():
    clear_auditd_cmd = ['auditctl', '-D']
    exec_clear_auditd_cmd = subprocess.run(clear_auditd_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


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

    # Clean auditd watches - we will add our own watches for this application
    remove_auditd_rules()

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
    dir_watcher_configs = dict(configs.items("DIR_WATCHER"))
    dirs_to_watch = dir_watcher_configs['dirs']
    dir_watcher_thread = Thread(
        target=dir_watcher.start_watcher,
        args=(dirs_to_watch, secure_socket, dir_watcher_configs['block_time'], threat_file, max_threat, mid_threat, default_threat)
    )
    thread_list.append(dir_watcher_thread)

    # Monitor user account changes
    user_watcher_configs = dict(configs.items('USER_WATCHER'))
    user_watcher_audit = user_watcher_configs['log']
    user_watcher_thread = Thread(
        target=user_watcher.start_user_watcher,
        args=(user_watcher_audit, secure_socket, user_watcher_configs['block_time'], threat_file, max_threat, mid_threat, default_threat, user_watcher_configs['passive_lower_time'])
    )
    thread_list.append(user_watcher_thread)

    # Monitor root/wheel logins
    root_watcher_configs = dict(configs.items('ROOT_WATCHER'))
    root_watcher_audit = root_watcher_configs['log']
    root_watcher_thread = Thread(
        target=root_watcher.start_root_watcher,
        args=(root_watcher_audit, secure_socket, root_watcher_configs['block_time'], threat_file, max_threat, mid_threat, default_threat, root_watcher_configs['passive_lower_time'])
    )
    thread_list.append(root_watcher_thread)
    
    # Monitor incoming SSH logins
    ssh_watcher_configs = dict(configs.items('SSH_WATCHER'))
    ssh_watcher_audit = ssh_watcher_configs['log']
    ssh_watcher_thread = Thread(
        target=ssh_watcher.start_ssh_watcher,
        args=(ssh_watcher_audit, secure_socket, ssh_watcher_configs['block_time'], threat_file, max_threat, mid_threat, default_threat, ssh_watcher_configs['passive_lower_time'])
    )
    thread_list.append(ssh_watcher_thread)

    # Monitor changes to firewalld
    firewalld_watcher_configs = dict(configs.items('FIREWALLD_WATCHER'))
    firewalld_watcher_audit = firewalld_watcher_configs['log']
    unallowed_services = firewalld_watcher_configs['unallowed_services'].split(',')
    unallowed_ports = firewalld_watcher_configs['unallowed_ports'].split(',')
    firewalld_watcher_thread = Thread(
        target=firewalld_watcher.start_firewalld_watcher,
        args=(firewalld_watcher_audit, secure_socket, threat_file, unallowed_services, unallowed_ports, max_threat, mid_threat, default_threat, firewalld_watcher_configs['passive_lower_time'])
    )
    thread_list.append(firewalld_watcher_thread)

    # Monitor certain commands
    cmd_watcher_configs = dict(configs.items('CMD_WATCHER'))
    cmd_watcher_audit = cmd_watcher_configs['log']
    blocked_cmds = cmd_watcher_configs['blocked_cmds']
    watched_cmds = cmd_watcher_configs['watched_cmds']
    cmd_watcher_thread = Thread(
        target=cmd_watcher.start_cmd_watcher,
        args=(cmd_watcher_audit, secure_socket, threat_file, blocked_cmds, watched_cmds, max_threat, mid_threat, default_threat, cmd_watcher_configs['block_time'], cmd_watcher_configs['passive_lower_time'])
    )
    thread_list.append(cmd_watcher_thread)

    # Start all watchers
    for thread in thread_list:
        thread.start()
        time.sleep(0.25)

    while True: 
        data = secure_socket.recv(4096)

        if data.decode('utf-8') == '$SHUTDOWN':
            print('\nshutdown signal received, exiting...')
            secure_socket.close()
            break
        elif not data:
            print('\nunexpected server shutdown, exiting...')
            secure_socket.close()
            break

    secure_socket.close()
    os._exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting program...")
        os._exit(0)
