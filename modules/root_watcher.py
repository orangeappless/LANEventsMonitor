import time
from datetime import datetime
import os


def start_root_watcher(audit_log, socket):
    file_size = os.stat(audit_log).st_size

    with open(audit_log, 'r') as log_file:
        log_file.seek(file_size)

        while True:
            new_data = log_file.read()

            if new_data:
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # Parse for root login commands in log entry
                # Currently tracks `sudo su`, `sudo -s`, `sudo su -`, `sudo -i`
                if 'USER_CMD' in new_data:
                    new_data = new_data.replace("'", " ")
                    new_data = new_data.replace('"', "")
                    new_data = new_data.split(' ')
                    data_attr = dict((s.split('=')+[1])[:2] for s in new_data)

                    data_attr['AUID'] = data_attr['AUID'].strip('\n')
                    data_attr['UID'] = data_attr.pop('\x1dUID')
                    # print(data_attr) 

                    if data_attr['exe'] == "/usr/bin/sudo" and (data_attr['cmd'] == "su" or data_attr['cmd'] == "/bin/bash" or data_attr['cmd'] == '7375202D' or data_attr['cmd'] == '-bash'):
                        if data_attr['res'] == 'success':
                            notification = f"[{current_time}] root login SUCCESS by \"{data_attr['UID']}\""
                            
                            print(notification)
                            socket.send(notification.encode('utf-8'))                            
                        elif data_attr['res'] == 'failed':
                            notification = f"[{current_time}] root login FAILED by \"{data_attr['UID']}\""
                            
                            print(notification)
                            socket.send(notification.encode('utf-8'))

            # time.sleep(1)
