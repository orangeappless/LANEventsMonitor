from datetime import datetime
import os
import subprocess
from threading import Timer

from utilities import audit_parser
from utilities import threat_mgmt


def block_su(operation, user, block_time, times_failed, threat_file, socket):
    # setfacl -m u:test:--- /bin/mkdir 
    # setfacl -x u:test /usr/bin/su 

    time_of_block = datetime.now().strftime("%Y-%m-%d %H:%M")
    block_notification = f"[{time_of_block}] possible INCIDENT, blocking `su` command for {user}"
    
    print(block_notification)
    socket.sendall(block_notification.encode('utf-8'))

    cmd = ['setfacl', '-m', f'u:{user}:---', '/usr/bin/su']
    exec_cmd = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Remove this rule after a set amount of time; however, if block_time is set to 0 (or less), block indefinitely
    if int(block_time) > 0:
        unblock_timer = Timer(int(block_time), unblock_su, args=(operation, user, times_failed, threat_file, socket))
        unblock_timer.start()


def unblock_su(operation, user, times_failed, threat_file, socket):
    time_of_unblock = datetime.now().strftime("%Y-%m-%d %H:%M")
    unblock_notification = f"[{time_of_unblock}] unblocking `su` command for {user}"

    cmd = ['setfacl', '-x', f'u:{user}', '/usr/bin/su']
    exec_cmd = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)    
   
    # Lower threat level after unblock
    if operation == 'root':
        threat_mgmt.update_threat('clear_failed_root', threat_file, times_failed)
    elif operation == 'wheel':
        threat_mgmt.update_threat('clear_failed_wheel', threat_file, times_failed)

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
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M")

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

                            # Evaluate threat level
                            current_threat_level = threat_mgmt.get_current_level(threat_file)

                            if current_threat_level >= int(threat_mid):
                                socket.sendall(notification.encode('utf-8'))

                            if current_threat_level >= int(threat_max):
                                threat_notification = threat_mgmt.create_max_threat_notif(threat_max, current_threat_level)
                                print(threat_notification)
                                socket.sendall(threat_notification.encode('utf-8'))

                                # Blocking action
                                block_su('root', data_attr['UID'], block_time, failed_root_attempts, threat_file, socket)

                                # Reset failed count, for next block attempt
                                failed_root_attempts = 0
                            elif current_threat_level >= int(threat_mid):
                                # Only send alert of event if mid level threat
                                threat_notification = threat_mgmt.create_mid_threat_notif(threat_mid, current_threat_level)
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
                            # notification = f"[{current_time}] `wheel` user \"{data_attr['acct']}\" login SUCCESS by \"{data_attr['UID']}\""
                            
                            # print(notification)
                            # socket.sendall(notification.encode('utf-8'))
                            threat_mgmt.update_threat('clear_failed_wheel', threat_file, failed_wheel_attempts)
                            failed_wheel_attempts = 0
                        elif data_attr['res'] == 'failed':
                            # Because user_watcher locks newly-added `wheel` accounts when the machine is at max threat level, trying
                            # to log into these locked accounts can fail. We don't want this to trigger a root_watcher alert, so we
                            # check for this first
                            check_lock = ['passwd', '--status', data_attr['acct']]
                            exec_check_lock = subprocess.run(check_lock, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            output = exec_check_lock.stdout.decode('utf-8')
                            
                            # If the account is not locked, proceed as intended
                            if 'Password locked.' not in output:
                                failed_wheel_attempts += 1
                                threat_mgmt.update_threat('failed_wheel', threat_file)

                                notification = f"[{current_time}] `wheel` user \"{data_attr['acct']}\" login FAILED by \"{data_attr['UID']}\""
                                print(notification)

                                current_threat_level = threat_mgmt.get_current_level(threat_file)

                                # If at or above mid threat, send notif to server
                                if current_threat_level >= int(threat_mid):
                                    socket.sendall(notification.encode('utf-8'))

                                if current_threat_level >= int(threat_max):
                                    # Block `su` at max threat
                                    threat_notification = threat_mgmt.create_max_threat_notif(threat_max, current_threat_level)
                                    print(threat_notification)
                                    socket.sendall(threat_notification.encode('utf-8'))

                                    block_su('wheel', data_attr['UID'], block_time, failed_wheel_attempts, threat_file, socket)
                                    failed_wheel_attempts = 0
                                elif current_threat_level >= int(threat_mid):
                                    threat_notification = threat_mgmt.create_mid_threat_notif(threat_mid, current_threat_level)
                                    print(threat_notification)
                                    socket.sendall(threat_notification.encode('utf-8'))
