from datetime import datetime
import os
import subprocess
from threading import Timer

from utilities import logger
from utilities import audit_parser
from utilities import threat_mgmt


def lock_created_users(created_users, block_time, threat_file, socket):
    time_of_lock = datetime.now().strftime("%Y-%m-%d %H:%M")

    if int(block_time) > 0:
        lock_notification = f"[{time_of_lock}] possible INCIDENT, locking newly-created users for {block_time} seconds"
    else:
        lock_notification = f"[{time_of_lock}] possible INCIDENT, locking newly-created users indefinitely"
    
    print(lock_notification)
    socket.sendall(lock_notification.encode('utf-8'))
    logger.logger(lock_notification)

    for user in created_users:
        lock_user = ['passwd', '-l' f'{user}']
        exec_lock_user = subprocess.run(lock_user, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Unlock users if unblock time is set
    if int(block_time) > 0:
        unlock_timer = Timer(int(block_time), unlock_created_users, args=(created_users, threat_file, socket))
        unlock_timer.start()


def unlock_created_users(created_users, threat_file, socket):
    time_of_unlock = datetime.now().strftime("%Y-%m-%d %H:%M")
    unlock_notification = f"[{time_of_unlock}] unlocking newly-created users"

    # Unlock users and adjust threat
    for user in created_users:
        unlock = ['passwd', '-u' f'{user}']
        exec_unlock = subprocess.run(unlock, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    threat_mgmt.update_threat('clear_create_user', threat_file, len(created_users))

    print(unlock_notification)
    socket.sendall(unlock_notification.encode('utf-8'))
    logger.logger(unlock_notification)


def block_usermod_wheel(wheel_user, user, block_time, times_failed, threat_file, socket):
    time_of_block = datetime.now().strftime("%Y-%m-%d %H:%M")

    if int(block_time) > 0:
        block_notification = f"[{time_of_block}] possible INCIDENT, locking new `wheel` user \"{wheel_user}\" for {block_time} seconds"
    else:
        block_notification = f"[{time_of_block}] possible INCIDENT, locking new `wheel` user \"{wheel_user}\" indefinitely"
    
    print(block_notification)
    socket.sendall(block_notification.encode('utf-8'))
    logger.logger(block_notification)

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
    logger.logger(unblock_notification)


def start_user_watcher(audit_log, socket, block_time, threat_file, threat_max, threat_mid, threat_default, passive_lower_time):
    created_users = []
    wheel_group_attempts = 0

    file_size = os.stat(audit_log).st_size

    with open(audit_log, 'r') as log_file:
        log_file.seek(file_size)

        while True:
            new_data = log_file.read()

            if new_data:
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M")  

                # User additions and deletions
                if new_data.startswith('type=ADD_USER'):
                    data_attr = audit_parser.get_audit_attrs(new_data)

                    threat_mgmt.update_threat('create_user', threat_file)
                    current_threat_level = threat_mgmt.get_current_level(threat_file)
                    action_threat = threat_mgmt.get_action_levels()['create_user']
                    created_users.append(data_attr['acct'])

                    # Handle threat
                    notification = f"[{current_time}] USER ADDED: \"{data_attr['acct']}\" by \"{data_attr['AUID']}\" ::: +{action_threat} [{current_threat_level}]"
                    print(notification)

                    if current_threat_level >= int(threat_mid):
                        socket.sendall(notification.encode('utf-8'))

                    logger.logger(notification)

                    # Lock newly-created user if at max threat-level
                    if current_threat_level >= int(threat_max):
                        threat_notification = threat_mgmt.create_max_threat_notif(threat_max, current_threat_level)
                        print(threat_notification)
                        socket.sendall(threat_notification.encode('utf-8'))
                        logger.logger(threat_notification)

                        # Block user
                        lock_created_users(created_users, block_time, threat_file, socket)
                        created_users = []
                    elif current_threat_level >= int(threat_mid):
                        threat_notification = threat_mgmt.create_mid_threat_notif(threat_mid, current_threat_level)
                        print(threat_notification)
                        socket.sendall(threat_notification.encode('utf-8'))
                        logger.logger(threat_notification)

                        # Passively lower threat if enabled
                        if int(passive_lower_time) > 0:
                            passive_lower = Timer(int(passive_lower_time), threat_mgmt.update_threat, args=('clear_create_user', threat_file))
                            passive_lower.start()
                            created_users.remove(data_attr['acct'])
                    else:
                        # If enabled, only passively lower threat
                        if int(passive_lower_time) > 0:
                            passive_lower = Timer(int(passive_lower_time), threat_mgmt.update_threat, args=('clear_create_user', threat_file))
                            passive_lower.start()
                            created_users.remove(data_attr['acct'])
                elif new_data.startswith('type=DEL_GROUP'):
                    data_attr = audit_parser.get_audit_attrs(new_data)

                    notification = f"[{current_time}] USER DELETED: \"{data_attr['acct']}\" by \"{data_attr['AUID']}\""
                    print(notification)
                    
                    current_threat_level = threat_mgmt.get_current_level(threat_file)

                    if current_threat_level >= int(threat_mid):
                        socket.sendall(notification.encode('utf-8')) 
                    
                    logger.logger(notification)

                # Check for additions to `wheel` group
                elif new_data.startswith('type=USER_MGMT') and 'add-user-to-group' in new_data and 'grp="wheel"' in new_data:
                    data_attr = audit_parser.get_audit_attrs(new_data)

                    if data_attr['grp'] == 'wheel':
                        threat_mgmt.update_threat('add_wheel_user', threat_file)
                        current_threat_level = threat_mgmt.get_current_level(threat_file)
                        action_threat = threat_mgmt.get_action_levels()['add_wheel_user']
                        wheel_group_attempts += 1
                        
                        notification = f"[{current_time}] user \"{data_attr['acct']}\" added to `wheel` group ::: +{action_threat} [{current_threat_level}]"
                        print(notification)

                        if current_threat_level >= int(threat_mid):
                            socket.sendall(notification.encode('utf-8'))

                        logger.logger(notification)

                        if current_threat_level >= int(threat_max):
                            threat_notification = threat_mgmt.create_max_threat_notif(threat_max, current_threat_level)
                            print(threat_notification)
                            socket.sendall(threat_notification.encode('utf-8'))
                            logger.logger(threat_notification)

                            block_usermod_wheel(data_attr['acct'], data_attr['UID'], block_time, wheel_group_attempts, threat_file, socket)
                            wheel_group_attempts = 0
                        elif current_threat_level >= int(threat_mid):
                            threat_notification = threat_mgmt.create_mid_threat_notif(threat_mid, current_threat_level)
                            print(threat_notification)
                            socket.sendall(threat_notification.encode('utf-8'))
                            logger.logger(threat_notification)

                            # Passively lower threat
                            if int(passive_lower_time) > 0:
                                passive_lower = Timer(int(passive_lower_time), threat_mgmt.update_threat, args=('clear_add_wheel_user', threat_file))
                                passive_lower.start()
                                wheel_group_attempts -= 1
                        else:
                            # Passively lower threat only
                            if int(passive_lower_time) > 0:
                                passive_lower = Timer(int(passive_lower_time), threat_mgmt.update_threat, args=('clear_add_wheel_user', threat_file))
                                passive_lower.start()
                                wheel_group_attempts -= 1
