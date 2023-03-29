from datetime import datetime
import os
import subprocess
from threading import Timer

from utilities import audit_parser
from utilities import threat_mgmt


def block_usermod_wheel(wheel_user, user, block_time, times_failed, threat_file, socket):
    time_of_block = datetime.now().strftime("%Y-%m-%d %H:%M")

    if int(block_time) > 0:
        block_notification = f"[{time_of_block}] possible INCIDENT, locking new `wheel` user \"{wheel_user}\" for {block_time} seconds"
    else:
        block_notification = f"[{time_of_block}] possible INCIDENT, locking new `wheel` user \"{wheel_user}\" indefinitely"
    
    print(block_notification)
    socket.sendall(block_notification.encode('utf-8'))

    # Lock newly-added `wheel` user
    lock_user_cmd = ['passwd', '-l', f'{wheel_user}']
    exec_lock_user = subprocess.run(lock_user_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Remove this rule after a set amount of time
    if int(block_time) > 0:
        unblock_timer = Timer(int(block_time), remove_block_usermod_wheel, args=(wheel_user, user, times_failed, threat_file, socket))
        unblock_timer.start()


def remove_block_usermod_wheel(wheel_user, user, times_attempted, threat_file, socket):
    time_of_unblock = datetime.now().strftime("%Y-%m-%d %H:%M")
    unblock_notification = f"[{time_of_unblock}] unlocking user \"{wheel_user}\" and removing from `wheel`"

    # Unlock user
    unlock_user_cmd = ['passwd', '-u', f'{wheel_user}']
    exec_unlock_user_cmd = subprocess.run(unlock_user_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Remove user from `wheel`
    remove_wheel_cmd = ['gpasswd', '-d', f'{wheel_user}', 'wheel']
    exec_remove_wheel_cmd = subprocess.run(remove_wheel_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Adjust threat
    threat_mgmt.update_threat('clear_add_wheel_user', threat_file, times_attempted)

    print(unblock_notification)
    socket.sendall(unblock_notification.encode('utf-8'))


def start_user_watcher(audit_log, socket, block_time, threat_file, threat_max, threat_mid, threat_default, passive_lower_time):
    wheel_group_attempts = 0

    file_size = os.stat(audit_log).st_size

    with open(audit_log, 'r') as log_file:
        log_file.seek(file_size)

        while True:
            new_data = log_file.read()

            if new_data:
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M")  

                if new_data.startswith('type=ADD_USER'):
                    data_attr = audit_parser.get_audit_attrs(new_data)

                    notification = f"[{current_time}] USER ADDED: \"{data_attr['acct']}\" by \"{data_attr['AUID']}\""
                    print(notification)
                    
                    current_threat_level = threat_mgmt.get_current_level(threat_file)

                    if current_threat_level >= int(threat_mid):
                        socket.sendall(notification.encode('utf-8'))
                elif new_data.startswith('type=DEL_GROUP'):
                    data_attr = audit_parser.get_audit_attrs(new_data)

                    notification = f"[{current_time}] USER DELETED: \"{data_attr['acct']}\" by \"{data_attr['AUID']}\""
                    print(notification)
                    
                    current_threat_level = threat_mgmt.get_current_level(threat_file)

                    if current_threat_level >= int(threat_mid):
                        socket.sendall(notification.encode('utf-8')) 
  
                # Check for additions to `wheel` group
                elif new_data.startswith('type=USER_MGMT') and 'add-user-to-group' in new_data and 'grp="wheel"' in new_data:
                    data_attr = audit_parser.get_audit_attrs(new_data)

                    if data_attr['grp'] == 'wheel':
                        wheel_group_attempts += 1

                        threat_mgmt.update_threat('add_wheel_user', threat_file)

                        notification = f"[{current_time}] user \"{data_attr['acct']}\" added to `wheel` group"
                        print(notification)

                        current_threat_level = threat_mgmt.get_current_level(threat_file)

                        if current_threat_level >= int(threat_mid):
                            socket.sendall(notification.encode('utf-8'))

                        if current_threat_level >= int(threat_max):
                            threat_notification = threat_mgmt.create_max_threat_notif(threat_max, current_threat_level)
                            print(threat_notification)
                            socket.sendall(threat_notification.encode('utf-8'))
        
                            block_usermod_wheel(data_attr['acct'], data_attr['UID'], block_time, wheel_group_attempts, threat_file, socket)
                            wheel_group_attempts = 0
                        elif current_threat_level >= int(threat_mid):
                            threat_notification = threat_mgmt.create_mid_threat_notif(threat_mid, current_threat_level)
                            print(threat_notification)
                            socket.sendall(threat_notification.encode('utf-8'))

                            # Passively lower threat
                            passive_lower = Timer(int(passive_lower_time), threat_mgmt.update_threat, args=('clear_add_wheel_user', threat_file))
                            passive_lower.start()
                            wheel_group_attempts -= 1
                        else:
                            # Passively lower threat only
                            passive_lower = Timer(int(passive_lower_time), threat_mgmt.update_threat, args=('clear_add_wheel_user', threat_file))
                            passive_lower.start()
                            wheel_group_attempts -= 1
