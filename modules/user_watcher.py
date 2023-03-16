import time
from datetime import datetime
import os

def start_user_watcher(audit_log, socket):
    audit_types = ['ADD_USER', 'DEL_USER']
    file_size = os.stat(audit_log).st_size

    with open(audit_log, 'r') as log_file:
        log_file.seek(file_size)

        while True:
            new_data = log_file.read()

            for audit_type in audit_types:
                if audit_type in new_data:
                    data_attr = new_data.split(' ')
                    data_attr = dict((s.split('=')+[1])[:2] for s in data_attr)
                    # print(data_attr)

                    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                    if data_attr['type'] == 'ADD_USER':
                            data_attr['AUID'] = data_attr['AUID'].strip('\n')
                            notification = f"[{current_time}] {data_attr['type']} {data_attr['acct']} by {data_attr['AUID']}"

                            print(notification)
                            socket.send(notification.encode('utf-8'))
                    elif data_attr['type'] == 'DEL_USER':
                        try:
                            data_attr['ID'] = data_attr['ID'].strip('\n')
                            notification = f"[{current_time}] {data_attr['type']} {data_attr['ID']} by {data_attr['AUID']}"

                            print(notification)
                            socket.send(notification.encode('utf-8'))
                        except:
                            print("User does not exist")

            # time.sleep(1)
