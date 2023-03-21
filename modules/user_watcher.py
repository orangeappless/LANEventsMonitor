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
                    socket.sendall(notification.encode('utf-8'))
                elif new_data.startswith('type=DEL_GROUP'):
                    data_attr = audit_parser.get_audit_attrs(new_data)

                    notification = f"[{current_time}] USER DELETED: \"{data_attr['acct']}\" by \"{data_attr['AUID']}\""

                    print(notification)
                    socket.sendall(notification.encode('utf-8'))           
