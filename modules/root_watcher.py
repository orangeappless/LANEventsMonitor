import time
from datetime import datetime
import os


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
                    new_data = new_data.replace("'", " ")
                    new_data = new_data.replace('"', "")
                    new_data = new_data.split(' ')
                    data_attr = dict((s.split('=')+[1])[:2] for s in new_data)

                    data_attr['AUID'] = data_attr['AUID'].strip('\n')
                    data_attr['UID'] = data_attr.pop('\x1dUID')
                    # print(data_attr) 

                    if data_attr['exe'] == "/usr/bin/sudo" and [cmd for cmd in root_login_cmds if(cmd in data_attr['cmd'])]:
                        if data_attr['res'] == 'success':
                            notification = f"[{current_time}] root login SUCCESS by \"{data_attr['UID']}\""
                            
                            print(notification)
                            socket.send(notification.encode('utf-8'))                            
                        elif data_attr['res'] == 'failed':
                            notification = f"[{current_time}] root login FAILED by \"{data_attr['UID']}\""
                            
                            print(notification)
                            socket.send(notification.encode('utf-8'))

            # time.sleep(1)
