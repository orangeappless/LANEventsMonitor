from datetime import datetime
import os
import subprocess
from threading import Timer

from utilities import audit_parser
from utilities import threat_mgmt


def block_addr(ip_addr, block_time, socket):
    time_of_block = datetime.now().strftime("%Y-%m-%d %H:%M")

    if int(block_time) > 0:
        block_notification = f"[{time_of_block}] possible INCIDENT at \"{ip_addr}\", blocking ssh for {block_time} seconds"
    else:
        block_notification = f"[{time_of_block}] possible INCIDENT at \"{ip_addr}\", blocking ssh indefinitely"
    
    print(block_notification)
    socket.sendall(block_notification.encode('utf-8'))

    cmd = ['iptables', '-A', 'INPUT', '-s', ip_addr, '-j', 'DROP']
    exec_cmd = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def remove_rule(ip_addr, socket, threat_file):
    time_of_unblock = datetime.now().strftime("%Y-%m-%d %H:%M")
    unblock_notification = f"[{time_of_unblock}] unblocking ssh rule for \"{ip_addr}\""

    cmd = ['iptables', '-D', 'INPUT', '-s', ip_addr, '-j', 'DROP']
    exec_cmd = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Decrease threat level caused by failed ssh attempts
    threat_mgmt.update_threat('clear_ssh', threat_file, failed_attempts[ip_addr])

    # Remove entry from dict
    remove_dict_entry(ip_addr)

    print(unblock_notification)
    socket.sendall(unblock_notification.encode('utf-8'))


def remove_dict_entry(ip_addr):
    failed_attempts.pop(ip_addr)


def start_ssh_watcher(log_file, socket, block_time, threat_file, threat_max, threat_mid, threat_default, passive_lower_time):
    global failed_attempts
    failed_attempts = {}

    file_size = os.stat(log_file).st_size

    with open(log_file, 'r') as log_file:
        log_file.seek(file_size)

        while True:
            new_data = log_file.read()

            if new_data:
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M")

                if 'USER_AUTH' and 'PAM:authentication' in new_data and '/usr/bin/su' not in new_data:
                    data_attr = audit_parser.get_audit_attrs(new_data)

                    if data_attr['terminal'] == 'ssh' and data_attr['res'] == 'failed':
                        # Update dict entry for failed IP
                        if data_attr['addr'] not in failed_attempts:
                            failed_attempts[data_attr['addr']] = 1

                            # Update threat level
                            threat_mgmt.update_threat('failed_ssh', threat_file)
                        else:
                            failed_attempts[data_attr['addr']] += 1

                            # Update threat level
                            threat_mgmt.update_threat('failed_ssh', threat_file)

                        current_threat_level = threat_mgmt.get_current_level(threat_file)
                        action_threat = threat_mgmt.get_action_levels()['failed_ssh']
                        
                        notification = f"[{current_time}] FAILED ssh attempt to \"{data_attr['acct']}\" by \"{data_attr['hostname']}\" ::: +{action_threat} [{current_threat_level}]"
                        print(notification)

                        if current_threat_level >= int(threat_mid):
                            socket.sendall(notification.encode('utf-8'))

                        if current_threat_level >= int(threat_max):
                            # Block IP if max level threat
                            threat_notification = threat_mgmt.create_max_threat_notif(threat_max, current_threat_level)
                            print(threat_notification)
                            socket.sendall(threat_notification.encode('utf-8'))

                            block_addr(data_attr['addr'], block_time, socket)

                            # Set timer to drop rule after n time - unless if block_time is set to 0, then block indefinitely
                            if int(block_time) > 0:
                                unblock_timer = Timer(int(block_time), remove_rule, args=(data_attr['addr'], socket, threat_file))
                                unblock_timer.start()
                        elif current_threat_level >= int(threat_mid):
                            # Only send alert of event if mid level threat
                            threat_notification = threat_mgmt.create_mid_threat_notif(threat_mid, current_threat_level)
                            print(threat_notification)
                            socket.sendall(threat_notification.encode('utf-8'))

                            # Passively lower threat
                            if int(passive_lower_time) > 0:
                                passive_lower = Timer(int(passive_lower_time), threat_mgmt.update_threat, args=('clear_ssh', threat_file))
                                passive_lower.start()
                        else:
                            # Passively lower threat
                            if int(passive_lower_time) > 0:
                                passive_lower = Timer(int(passive_lower_time), threat_mgmt.update_threat, args=('clear_ssh', threat_file))
                                passive_lower.start()

                    elif data_attr['terminal'] == 'ssh' and data_attr['res'] == 'success' and data_attr['addr'] in failed_attempts:
                        # Clear threat level upon successful login
                        threat_mgmt.update_threat('success_ssh', threat_file, failed_attempts[data_attr['addr']])

                        # Clear failed dict entry upon successful login
                        failed_attempts.pop(data_attr['addr'])
