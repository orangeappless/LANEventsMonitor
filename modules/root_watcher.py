from datetime import datetime
import os
import subprocess
from threading import Timer

from utilities import audit_parser
from utilities import threat_mgmt


def block_su(user, block_time, times_failed, threat_file, socket):
    # setfacl -m u:test:--- /bin/mkdir 
    # setfacl -x u:test /usr/bin/su 

    time_of_block = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    block_notification = f"[{time_of_block}] blocking `su` command for {user}"
    
    print(block_notification)
    socket.sendall(block_notification.encode('utf-8'))

    cmd = ['setfacl', '-m', f'u:{user}:---', '/usr/bin/su']
    exec_cmd = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Remove this rule after a set amount of time
    unblock_timer = Timer(int(block_time), unblock_su, args=(user, times_failed, threat_file, socket))
    unblock_timer.start()


def unblock_su(user, times_failed, threat_file, socket):
    time_of_unblock = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    unblock_notification = f"[{time_of_unblock}] unblocking `su` command for {user}"

    cmd = ['setfacl', '-x', f'u:{user}', '/usr/bin/su']
    exec_cmd = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)    
   
    # Lower threat level after unblock
    threat_mgmt.update_threat('clear_failed_root', threat_file, times_failed)

    print(unblock_notification)
    socket.sendall(unblock_notification.encode('utf-8'))


def start_root_watcher(audit_log, socket, block_time, threat_file, threat_max, threat_mid, threat_default):
    root_login_cmds = [
        'su',           # `sudo su`
        '/bin/bash',    # `sudo -s`
        '7375202D',     # `sudo su -`
        '-bash'         # `sudo -i`
    ]

    failed_root_attempts = 0
    failed_wheel_attempts = 0

    file_size = os.stat(audit_log).st_size

    with open(audit_log, 'r') as log_file:
        log_file.seek(file_size)

        while True:
            new_data = log_file.read()

            if new_data:
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # Parse for root login commands in log entry
                if 'USER_CMD' in new_data:
                    data_attr = audit_parser.get_audit_attrs(new_data)

                    if data_attr['exe'] == "/usr/bin/sudo" and [cmd for cmd in root_login_cmds if(cmd in data_attr['cmd'])]:
                        if data_attr['res'] == 'success':
                            # notification = f"[{current_time}] root login SUCCESS by \"{data_attr['UID']}\""
                            
                            # print(notification)
                            # socket.sendall(notification.encode('utf-8'))

                            # Reset threat and count caused by failed root logins
                            threat_mgmt.update_threat('success_root', threat_file, failed_root_attempts)
                            failed_root_attempts = 0
                        elif data_attr['res'] == 'failed':
                            failed_root_attempts += 1
                            
                            # Update threat level
                            threat_mgmt.update_threat('failed_root', threat_file)

                            notification = f"[{current_time}] root login FAILED by \"{data_attr['UID']}\""
                            
                            print(notification)
                            socket.sendall(notification.encode('utf-8'))

                            # Evaluate threat level
                            current_threat_level = threat_mgmt.get_current_level(threat_file)

                            if current_threat_level >= int(threat_max):
                                # Blocking action
                                block_su(data_attr['UID'], block_time, failed_root_attempts, threat_file, socket)

                                # Reset failed count, for next block attempt
                                failed_root_attempts = 0
                            elif current_threat_level >= int(threat_mid):
                                # Only send alert of event if mid level threat
                                threat_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                threat_notification = f'[{threat_time}] system at MEDIUM THREAT LEVEL ({threat_mid})'

                                print(threat_notification)
                                socket.sendall(threat_notification.encode('utf-8'))
                
                # Parse attempted logins to non-root accounts in `wheel` group
                elif 'USER_AUTH' in new_data and 'acct="root"' not in new_data and 'terminal=ssh' not in new_data:
                    data_attr = audit_parser.get_audit_attrs(new_data)

                    # Parse `wheel` group in `/etc/group`
                    cat_cmd = subprocess.Popen(['cat', '/etc/group'], stdout=subprocess.PIPE, shell=False)
                    grep_cmd = subprocess.Popen(['grep', 'wheel:x'], stdin=cat_cmd.stdout, stdout=subprocess.PIPE, shell=False)
                    cat_cmd.stdout.close()
                    output = grep_cmd.communicate()[0]

                    # Clean output and get users of `wheel` group
                    wheel_users = output.decode('utf-8').split(':')[-1]
                    wheel_users = wheel_users.strip('\n')
                    wheel_users_list = wheel_users.split(',')

                    # Check if target user is in `wheel`
                    if data_attr['acct'] in wheel_users_list:
                        if data_attr['res'] == 'success':
                            notification = f"[{current_time}] `wheel` user \"{data_attr['acct']}\" login SUCCESS by \"{data_attr['UID']}\""
                            
                            print(notification)
                            socket.sendall(notification.encode('utf-8'))                         
                        elif data_attr['res'] == 'failed':
                            notification = f"[{current_time}] `wheel` user \"{data_attr['acct']}\" login FAILED by \"{data_attr['UID']}\""

                            print(notification)
                            socket.sendall(notification.encode('utf-8'))
