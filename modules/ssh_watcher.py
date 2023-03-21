from datetime import datetime
import os
import subprocess
from threading import Timer

from utilities import audit_parser


def block_addr(ip_addr, block_time, socket):
    time_of_block = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    block_notification = f"[{time_of_block}] max failed ssh attempts reached for \"{ip_addr}\", blocking for {block_time} seconds"

    cmd = ['iptables', '-A', 'INPUT', '-s', ip_addr, '-j', 'DROP']
    exec_cmd = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    print(block_notification)
    socket.send(block_notification.encode('utf-8'))


def remove_rule(ip_addr, socket):
    time_of_unblock = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    unblock_notification = f"[{time_of_unblock}] unblocking ssh rule for \"{ip_addr}\""

    cmd = ['iptables', '-D', 'INPUT', '-s', ip_addr, '-j', 'DROP']
    exec_cmd = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Remove entry from dict
    remove_dict_entry(ip_addr)

    print(unblock_notification)
    socket.send(unblock_notification.encode('utf-8'))


def remove_dict_entry(ip_addr):
    failed_attempts.pop(ip_addr)


def start_ssh_watcher(log_file, socket, max_failed, block_time):
    global failed_attempts
    failed_attempts = {}

    file_size = os.stat(log_file).st_size

    with open(log_file, 'r') as log_file:
        log_file.seek(file_size)

        while True:
            new_data = log_file.read()

            if new_data:
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                if 'USER_AUTH' and 'PAM:authentication' in new_data and '/usr/bin/su' not in new_data:
                    # new_data = new_data.replace("'", " ")
                    # new_data = new_data.replace('"', "")
                    # new_data = new_data.split(' ')
                    # data_attr = dict((s.split('=')+[1])[:2] for s in new_data)

                    # data_attr['AUID'] = data_attr['AUID'].strip('\n')
                    # data_attr['UID'] = data_attr.pop('\x1dUID')
                    #print(data_attr)

                    data_attr = audit_parser.get_audit_attrs(new_data)

                    if data_attr['terminal'] == 'ssh' and data_attr['res'] == 'failed':
                        # Update dict entry for failed IP
                        if data_attr['addr'] not in failed_attempts:
                            failed_attempts[data_attr['addr']] = 1
                            # print(failed_attempts)
                        else:
                            failed_attempts[data_attr['addr']] += 1
                            # print(failed_attempts)

                        addr_failed_attempts = f"failed attempts: {failed_attempts[data_attr['addr']]}"
                        notification = f"[{current_time}] FAILED ssh attempt to \"{data_attr['acct']}\" by \"{data_attr['hostname']}\", {addr_failed_attempts}"

                        print(notification)
                        socket.send(notification.encode('utf-8'))

                        if failed_attempts[data_attr['addr']] >= int(max_failed):
                            # Block address after reaching max attempts
                            block_addr(data_attr['addr'], block_time, socket)

                            # Set timer to drop rule after n time
                            unblock_timer = Timer(int(block_time), remove_rule, args=(data_attr['addr'], socket))
                            unblock_timer.start()
                    elif data_attr['terminal'] == 'ssh' and data_attr['res'] == 'success' and data_attr['addr'] in failed_attempts:
                        # Clear failed dict entry upon successful login
                        failed_attempts.pop(data_attr['addr'])
