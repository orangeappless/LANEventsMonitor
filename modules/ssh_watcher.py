from datetime import datetime
import os


def start_ssh_watcher(log_file, socket):
    file_size = os.stat(log_file).st_size

    with open(log_file, 'r') as log_file:
        log_file.seek(file_size)

        while True:
            new_data = log_file.read()

            if new_data:
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                if 'USER_AUTH' and 'PAM:authentication' in new_data:
                    new_data = new_data.replace("'", " ")
                    new_data = new_data.replace('"', "")
                    new_data = new_data.split(' ')
                    data_attr = dict((s.split('=')+[1])[:2] for s in new_data)

                    data_attr['AUID'] = data_attr['AUID'].strip('\n')
                    data_attr['UID'] = data_attr.pop('\x1dUID')
                    #print(data_attr) 

                    if data_attr['terminal'] == 'ssh' and data_attr['res'] == 'failed':
                        notification = f"[{current_time}] FAILED ssh attempt to \"{data_attr['acct']}\" by \"{data_attr['hostname']}\""

                        print(notification)
                        socket.send(notification.encode('utf-8'))
