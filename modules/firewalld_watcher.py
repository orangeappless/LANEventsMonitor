from datetime import datetime
import os
import subprocess

from utilities import audit_parser
from utilities import threat_mgmt


def check_auditd_rule(auditd_rule):
    # Checks for the existence of an auditd rule
    check_auditd_rules_cmd = ['auditctl', '-l']
    exec_cmd = subprocess.run(check_auditd_rules_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if auditd_rule in exec_cmd.stdout.decode('utf-8'):
        return True
    else:
        return False


def init_auditd_rule(auditd_rule):
    # Adds specified auditd rule if it doesn't alrady exist
    # auditctl -w /usr/bin/firewall-cmd -p x -k firewall-cmd
    auditd_rule_split = auditd_rule.split(' ')
    auditd_rule_split.insert(0, 'auditctl')
    
    auditd_cmd = auditd_rule_split
    exec_cmd = subprocess.run(auditd_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    print('auditd watch for firewalld_watcher created')


def undo_firewalld_rule(added_services, threat_file, socket):
    time_of_block = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    block_notification = f"[{time_of_block}] possible INCIDENT, removing recently-added services/ports from firewalld"
  
    print(block_notification)
    socket.sendall(block_notification.encode('utf-8'))

    for service in added_services:
        if '/tcp' in service:
            cmd = ['firewall-cmd', f'--remove-port={service}']
        else:
            cmd = ['firewall-cmd', f'--remove-service={service}']
        
        exec_cmd = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Updated threat based on removed rules
    threat_mgmt.update_threat('clear_add_unallowed_service', threat_file, len(added_services))


def start_firewalld_watcher(log_file, socket, threat_file, unallowed_services_list, unallowed_ports_list, threat_max, threat_mid, threat_default):
    rules_added = []

    auditd_rule = '-w /usr/bin/firewall-cmd -p x -k firewall-cmd'
    auditd_rule_exists = check_auditd_rule(auditd_rule)

    if auditd_rule_exists == False:
        # Create auditd rule if it doesn't exist
        init_auditd_rule(auditd_rule)

    file_size = os.stat(log_file).st_size

    with open(log_file, 'r') as log:
        log.seek(file_size)

        while True:
            new_data = log.read()

            if new_data:
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                if 'type=EXECVE' in new_data and 'firewall-cmd' in new_data:
                    data_list = new_data.split('\n')

                    # Grab EXECVE audits only
                    for data in data_list:
                        if data.startswith('type=EXECVE'):
                            # Split data into attrs
                            data = data.replace("'", " ")
                            data = data.replace('"', "")
                            data = data.replace("\n", "")
                            data = data.split(' ')

                            # 'a3' is the firewall-cmd command
                            command = data[6]

                            # Parse for --add-service modifications
                            if '--add-service' in command:
                                # Clean output and get nanme of added service
                                command = command.split('=')
                                added_service = command[2]

                                # Only trigger on added services on blacklist
                                if added_service in unallowed_services_list:
                                    # Update threat on blacklisted service
                                    threat_mgmt.update_threat('add_unallowed_service', threat_file)
                                    rules_added.append(added_service)

                                    notification = f"[{current_time}] service \"{added_service}\" opened by firewalld"

                                    print(notification)
                                    socket.sendall(notification.encode('utf-8'))
                                    
                                    # Evaluate threat level
                                    current_threat_level = threat_mgmt.get_current_level(threat_file)

                                    if current_threat_level >= int(threat_max):
                                        # Undo previous firewall rule and block firewall-cmd command
                                        threat_notification = threat_mgmt.create_max_threat_notif(threat_max, current_threat_level)
                                        print(threat_notification)
                                        socket.sendall(threat_notification.encode('utf-8'))

                                        undo_firewalld_rule(rules_added, threat_file, socket)
                                        rules_added.clear()
                                    elif current_threat_level >= int(threat_mid):
                                        # Only send alert of event if mid level threat
                                        threat_notification = threat_mgmt.create_mid_threat_notif(threat_mid, current_threat_level)
                                        print(threat_notification)
                                        socket.sendall(threat_notification.encode('utf-8'))

                            # Trigger on unallowed ports
                            elif '--add-port' in command:
                                command = command.split('=')
                                added_port = command[2]
                                
                                if added_port in unallowed_ports_list:
                                    threat_mgmt.update_threat('add_unallowed_port', threat_file)
                                    rules_added.append(added_port)

                                    notification = f"[{current_time}] port \"{added_port}\" opened by firewalld"

                                    print(notification)
                                    socket.sendall(notification.encode('utf-8'))

                                    current_threat_level = threat_mgmt.get_current_level(threat_file)
                                    
                                    if current_threat_level >= int(threat_max):
                                        # Undo previous firewall rule and block firewall-cmd command
                                        threat_notification = threat_mgmt.create_max_threat_notif(threat_max, current_threat_level)
                                        print(threat_notification)
                                        socket.sendall(threat_notification.encode('utf-8'))

                                        undo_firewalld_rule(rules_added, threat_file, socket)
                                        rules_added.clear()
                                    elif current_threat_level >= int(threat_mid):
                                        # Only send alert of event if mid level threat
                                        threat_notification = threat_mgmt.create_mid_threat_notif(threat_mid, current_threat_level)
                                        print(threat_notification)
                                        socket.sendall(threat_notification.encode('utf-8'))
