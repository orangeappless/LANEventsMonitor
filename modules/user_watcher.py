import time
from datetime import datetime
import os

from utilities import audit_parser

def start_user_watcher(audit_log, socket):
    file_size = os.stat(audit_log).st_size

    with open(audit_log, 'r') as log_file:
        log_file.seek(file_size)

        while True:
            new_data = log_file.read()

            if new_data:
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  

                if new_data.startswith('type=ADD_USER'):
                    data_attr = audit_parser.get_audit_attrs(new_data)

                    notification = f"[{current_time}] USER ADDED: \"{data_attr['acct']}\" by \"{data_attr['AUID']}\""

                    print(notification)
                    socket.send(notification.encode('utf-8'))
                elif new_data.startswith('type=DEL_GROUP'):
                    data_attr = audit_parser.get_audit_attrs(new_data)

                    notification = f"[{current_time}] USER DELETED: \"{data_attr['acct']}\" by \"{data_attr['AUID']}\""

                    print(notification)
                    socket.send(notification.encode('utf-8'))           

            # for audit_type in audit_types:
            #     if audit_type in new_data:
            #         current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            #         new_data = new_data.split('type=')

            #         for data in new_data:
            #             if data.startswith('ADD_GROUP'):
            #                 data_attr = new_data[2].split(' ')
            #                 data_attr = dict((s.split('=')+[1])[:2] for s in data_attr)
            #                 # print(data_attr)
        
            #                 data_attr['AUID'] = data_attr['AUID'].strip('\n')
            #                 notification = f"[{current_time}] USER ADDED: {data_attr['acct']} by {data_attr['AUID']}"

            #                 print(notification)
            #                 socket.send(notification.encode('utf-8'))
            #             elif data.startswith('DEL_USER'):
            #                 try:
            #                     data_attr = new_data[2].split(' ')
            #                     data_attr = dict((s.split('=')+[1])[:2] for s in data_attr)
            #                     # print(data_attr)

            #                     data_attr['AUID'] = data_attr['AUID'].strip('\n')
            #                     notification = f"[{current_time}] USER DELETED: {data_attr['acct']} by {data_attr['AUID']}"

            #                     print(notification)
            #                     socket.send(notification.encode('utf-8'))
            #                 except:
            #                     print("Tried to remove a user which does not exist")

            # time.sleep(1)
