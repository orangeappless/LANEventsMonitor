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


def start_firewalld_watcher(log_file, socket):
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

                if 'type=EXECVE' in new_data:
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

                                notification = f"[{current_time}] service \"{added_service}\" opened by firewalld"

                                print(notification)
                                socket.sendall(notification.encode('utf-8'))
      