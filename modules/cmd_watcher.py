from datetime import datetime
import os
import subprocess
from threading import Timer

from utilities import audit_parser
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
    

def start_cmd_watcher(audit_log, socket, threat_file, blocked_cmds, watched_cmds, threat_max, threat_mid, threat_default, block_time):
    init_auditd_rules(blocked_cmds, 'blocked-cmd')
    init_auditd_rules(watched_cmds, 'watched-cmd')
