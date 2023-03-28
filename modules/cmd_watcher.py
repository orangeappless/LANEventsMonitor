from datetime import datetime
import os
import subprocess
from threading import Timer

from utilities import threat_mgmt


def init_auditd_rules(cmds_to_add, type):
    cmds = cmds_to_add.split(',')
    binaries = []

    # Find location of binaries first
    for cmd in cmds:
        which_cmd = ['which', cmd]
        exec_which_cmd = subprocess.run(which_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = exec_which_cmd.stdout.decode('utf-8').strip('\n')
        binaries.append(output)

    # Add auditd rules
    for binary in binaries:
        auditd_cmd = ['auditctl', '-w', f'{binary}', '-p', 'x', '-k', f'{type}']
        exec_auditd_cmd = subprocess.run(auditd_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    if type == 'blocked-cmd':
        print(f'audid watches for blocked cmds \"{cmds_to_add}\" created')
    else:
        print(f'audid watches for watched cmds \"{cmds_to_add}\" created')


def block_blocked_cmds(blocked_cmds):
    # setfacl -m o:--- /usr/bin/telnet
    # setfacl -m o:rx /usr/bin/telnet
    cmds = blocked_cmds.split(',')
    binaries = []

    # Find location of binaries first
    for cmd in cmds:
        which_cmd = ['which', cmd]
        exec_which_cmd = subprocess.run(which_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = exec_which_cmd.stdout.decode('utf-8').strip('\n')
        binaries.append(output)

    for binary in binaries:
        cmd = ['setfacl', '-m', 'o::---', f'{binary}']
        exec_cmd = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # print(binaries)
    print(f'facl rule automatically set for blocked cmds \"{blocked_cmds}\"')


def block_watched_cmds(executed_cmds, user, block_time, threat_file, socket):
    # setfacl -m u:username:--- /path/to/binary
    # setfacl -x u:username /path/to/binary
    for cmd in executed_cmds:
        # Use setfacl to block user access to these commands
        block_cmd = ['setfacl', '-m', f'u:{user}:---', f'{cmd}']
        exec_block_cmd = subprocess.run(block_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    time_of_block = datetime.now().strftime("%Y-%m-%d %H:%M")
    block_notification = f"[{time_of_block}] possible INCIDENT, blocking watchlisted command(s) for \"{user}\""
    
    print(block_notification)
    socket.sendall(block_notification.encode('utf-8'))

    # Unblock after block timing has expired
    unblock_cmds_timer = Timer(int(block_time), unblock_watched_cmds, args=(executed_cmds, user, threat_file, socket))
    unblock_cmds_timer.start()


def unblock_watched_cmds(executed_cmds, user, threat_file, socket):
    time_of_unblock = datetime.now().strftime("%Y-%m-%d %H:%M")
    unblock_notification = f"[{time_of_unblock}] unblocking watchlisted command(s) for {user}"

    for cmd in executed_cmds:
        unblock_cmd = ['setfacl', '-x', f'u:{user}', f'{cmd}']
        exec_unblock_cmd = subprocess.run(unblock_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    threat_mgmt.update_threat('clear_exec_watched_cmd', threat_file, len(executed_cmds))

    print(unblock_notification)
    socket.sendall(unblock_notification.encode('utf-8'))


def start_cmd_watcher(audit_log, socket, threat_file, blocked_cmds, watched_cmds, threat_max, threat_mid, threat_default, block_time):
    init_auditd_rules(blocked_cmds, 'blocked-cmd')
    init_auditd_rules(watched_cmds, 'watched-cmd')

    # Use setfacl to block blocked_cmds right away
    block_blocked_cmds(blocked_cmds)

    executed_watched_cmds = []

    file_size = os.stat(audit_log).st_size

    with open(audit_log, 'r') as log_file:
        log_file.seek(file_size)

        while True:
            new_data = log_file.read()

            if new_data:
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M")

                if 'watched-cmd' in new_data:
                    new_data = new_data.split('type=')

                    # We want only the SYSCALL and EXECVE entries
                    syscall_entry = ''
                    execve_entry = ''

                    for data in new_data:
                        if data.startswith('SYSCALL'):
                            syscall_entry = data
                        
                        if data.startswith('EXECVE'):
                            execve_entry = data
                    
                    # Process syscall_entry and execve_entry
                    syscall_entry = syscall_entry.replace('"', "")
                    syscall_entry = syscall_entry.split(' ')
                    syscall_attrs = dict((s.split('=')+[1])[:2] for s in syscall_entry)
                    # print(syscall_attrs)

                    execve_entry = execve_entry.replace('"', "")
                    execve_entry = execve_entry.split(' ')
                    execve_attrs = dict((s.split('=')+[1])[:2] for s in execve_entry)
                    # print(execve_attrs)

                    # Handle threat level
                    if syscall_attrs['exe'] != '/usr/bin/bash':
                        threat_mgmt.update_threat('exec_watched_cmd', threat_file)
                        executed_watched_cmds.append(syscall_attrs['exe'])

                        notification = f"[{current_time}] watchlisted command `{syscall_attrs['exe']}` executed by \"{syscall_attrs['UID']}\""
                        print(notification)

                        current_threat_level = threat_mgmt.get_current_level(threat_file)

                        if current_threat_level >= int(threat_mid):
                            socket.sendall(notification.encode('utf-8'))

                        if current_threat_level >= int(threat_max):
                            # Undo previous firewall rule and block firewall-cmd command
                            threat_notification = threat_mgmt.create_max_threat_notif(threat_max, current_threat_level)
                            print(threat_notification)
                            socket.sendall(threat_notification.encode('utf-8'))

                            block_watched_cmds(executed_watched_cmds, syscall_attrs['UID'], block_time, threat_file, socket)
                            executed_watched_cmds = []
                        elif current_threat_level >= int(threat_mid):
                            # Only send alert of event if mid level threat
                            threat_notification = threat_mgmt.create_mid_threat_notif(threat_mid, current_threat_level)
                            print(threat_notification)
                            socket.sendall(threat_notification.encode('utf-8'))                    
