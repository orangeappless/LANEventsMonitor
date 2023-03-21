from datetime import datetime
import os
import subprocess

from utilities import audit_parser


def start_root_watcher(audit_log, socket):
    root_login_cmds = [
        'su',           # `sudo su`
        '/bin/bash',    # `sudo -s`
        '7375202D',     # `sudo su -`
        '-bash'         # `sudo -i`
    ]

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
                            notification = f"[{current_time}] root login SUCCESS by \"{data_attr['UID']}\""
                            
                            print(notification)
                            socket.sendall(notification.encode('utf-8'))                            
                        elif data_attr['res'] == 'failed':
                            notification = f"[{current_time}] root login FAILED by \"{data_attr['UID']}\""
                            
                            print(notification)
                            socket.sendall(notification.encode('utf-8'))
                
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
