import pyinotify
from datetime import datetime
from threading import Timer
import os.path

from utilities import threat_mgmt


class EventHandler(pyinotify.ProcessEvent):
    def __init__(self):
        self.last_modified_time = None

    def process_IN_CREATE(self, event):
        if "swp" in event.name or "swpx" in event.name or ".part" in event.name or event.name[-1] == "+" or event.name[-1] == "-" or ".lock" in event.name or '~' in event.name:
            return
        
        if (event.name).isdigit():
            return
        
        # Creation in directory
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M")  
        notification = f"[{current_time}] CREATED: {event.pathname}"

        print(notification)
        self.send_notif(notification)

    def process_IN_DELETE(self, event):
        if "swp" in event.name or "swpx" in event.name or ".part" in event.name or event.name[-1] == "+" or event.name[-1] == "-" or ".lock" in event.name or '~' in event.name:
            return

        if (event.name).isdigit():
            return
        
        # Ignore modifications of login logs - this contains failed login attempts, and is
        # monitored by other watchers in the app
        login_logs = ['btmp', 'utmp', 'wtmp', 'lastlog']
        if event.name in login_logs:
            return

        # # Catch only if triggered in a limited time; prevents mass notifications from system logs
        # modified_time = os.path.getmtime(event.pathname)

        # if self.last_modified_time is not None and modified_time - self.last_modified_time < 3:
        #     return

        # self.last_modified_time = modified_time

        # Deletion in directory
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M")  

        # Update threat level
        threat_mgmt.update_threat('dir_modification', threat_file_)
        current_threat_level = threat_mgmt.get_current_level(threat_file_)
        action_threat = threat_mgmt.get_action_levels()['dir_modification']

        notification = f"[{current_time}] DELETED item in watched directory \"{event.pathname}\" ::: +{action_threat} [{current_threat_level}]"
        print(notification)

        # Send notification to server only if system is at mid threat or higher
        if current_threat_level >= int(mid_threat):
            self.send_notif(notification)

        if current_threat_level >= int(max_threat):
            threat_notification = threat_mgmt.create_max_threat_notif(max_threat, current_threat_level)
            print(threat_notification)
            socket_.sendall(threat_notification.encode('utf-8'))
        elif current_threat_level >= int(mid_threat):
            threat_notification = threat_mgmt.create_mid_threat_notif(mid_threat, current_threat_level)
            print(threat_notification)
            socket_.sendall(threat_notification.encode('utf-8'))
    
            lower_threat_timer = Timer(int(block_time), self.lower_threat)
            lower_threat_timer.start()

    def process_IN_CLOSE_WRITE(self, event):
        if "swp" in event.name or "swpx" in event.name or ".part" in event.name or event.name[-1] == "+" or event.name[-1] == "-" or ".lock" in event.name or '~' in event.name:
            return

        if (event.name).isdigit():
            return

        # Ignore modifications of login logs - this contains failed login attempts, and is
        # monitored by other watchers in the app
        login_logs = ['btmp', 'utmp', 'wtmp', 'lastlog', 'sssd.log', 'sssd_nss.log', 'sssd_implicit_files.log']
        if event.name in login_logs:
            return
        
        # Limit time
        modified_time = os.path.getmtime(event.pathname)

        if self.last_modified_time is not None and modified_time - self.last_modified_time < 3:
            return

        self.last_modified_time = modified_time

        # Change in file in directory
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M")

        # Update threat level
        threat_mgmt.update_threat('dir_modification', threat_file_)
        current_threat_level = threat_mgmt.get_current_level(threat_file_)
        action_threat = threat_mgmt.get_action_levels()['dir_modification']

        notification = f"[{current_time}] MODIFIED item in watched directory \"{event.pathname}\" ::: +{action_threat} [{current_threat_level}]"
        print(notification)

        # Send notification to server only if system is at mid threat or higher
        if current_threat_level >= int(mid_threat):
            self.send_notif(notification)

        if current_threat_level >= int(max_threat):
            threat_notification = threat_mgmt.create_max_threat_notif(max_threat, current_threat_level)
            print(threat_notification)
            socket_.sendall(threat_notification.encode('utf-8'))
        elif current_threat_level >= int(mid_threat):
            threat_notification = threat_mgmt.create_mid_threat_notif(mid_threat, current_threat_level)
            print(threat_notification)
            socket_.sendall(threat_notification.encode('utf-8'))

        if int(block_time) > 0:
            lower_threat_timer = Timer(int(block_time), self.lower_threat)
            lower_threat_timer.start()

    def send_notif(self, notification):
        socket_.sendall(notification.encode("utf-8"))

    def lower_threat(self):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M")

        threat_mgmt.update_threat('clear_dir_modification', threat_file_)
        current_threat_level = threat_mgmt.get_current_level(threat_file_)
        action_threat = threat_mgmt.get_action_levels()['clear_dir_modification']

        notification = f'[{current_time}] threat from directory modification/deletion lowered ::: {action_threat} [{current_threat_level}]'
        print(notification)
        socket_.sendall(notification.encode('utf-8'))


def start_watcher(directories, socket, time_block, threat_file, threat_max, threat_mid, threat_default):
    # Assign globals to be used
    global socket_, block_time, threat_file_, max_threat, mid_threat, default_threat
    socket_ = socket
    block_time = time_block
    threat_file_ = threat_file
    max_threat = threat_max
    mid_threat = threat_mid
    default_threat = threat_default

    watch_manager = pyinotify.WatchManager()
    mask = pyinotify.IN_DELETE | pyinotify.IN_CLOSE_WRITE
    
    notifier = pyinotify.ThreadedNotifier(watch_manager, EventHandler())

    dirs_to_watch = directories.split(',')

    # Iterate over given directory list
    for dir in dirs_to_watch:
        watch_manager.add_watch(dir, mask, rec=True)

    notifier.start()
