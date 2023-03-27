import pyinotify
import socket
from datetime import datetime

from utilities import threat_mgmt


class EventHandler(pyinotify.ProcessEvent):
    def process_IN_CREATE(self, event):
        if "swp" in event.name or "swpx" in event.name or ".part" in event.name or event.name[-1] == "+" or event.name[-1] == "-" or ".lock" in event.name or "." in event.name or '~' in event.name:
            return
        
        if (event.name).isdigit():
            return
        
        # Creation in directory
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  
        notification = f"[{current_time}] CREATED: {event.pathname}"

        print(notification)
        self.send_notif(notification)

    def process_IN_DELETE(self, event):
        if "swp" in event.name or "swpx" in event.name or ".part" in event.name or event.name[-1] == "+" or event.name[-1] == "-" or ".lock" in event.name or "." in event.name or '~' in event.name:
            return

        if (event.name).isdigit():
            return

        # Deletion in directory
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  
        notification = f"[{current_time}] DELETED: {event.pathname}"

        print(notification)
        self.send_notif(notification)

        # Update threat level
        threat_mgmt.update_threat('dir_modification', threat_file_)

        current_threat_level = threat_mgmt.get_current_level(threat_file_)

        if current_threat_level >= int(max_threat):
            threat_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            threat_notification = f'[{threat_time}] system at MAX THREAT LEVEL ({max_threat}), possible INCIDENT'

            print(threat_notification)
            socket_.sendall(threat_notification.encode('utf-8'))
        elif current_threat_level >= int(mid_threat):
            threat_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            threat_notification = f'[{threat_time}] system at MEDIUM THREAT LEVEL ({mid_threat})'

            print(threat_notification)
            socket_.sendall(threat_notification.encode('utf-8'))
    
    def process_IN_CLOSE_WRITE(self, event):
        if "swp" in event.name or "swpx" in event.name or ".part" in event.name or event.name[-1] == "+" or event.name[-1] == "-" or ".lock" in event.name or "." in event.name or '~' in event.name:
            return

        if (event.name).isdigit():
            return

        # Change in file in directory
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  
        notification = f"[{current_time}] MODIFIED: {event.pathname}"

        print(notification)
        self.send_notif(notification)

        # Update threat level
        threat_mgmt.update_threat('dir_modification', threat_file_)

        current_threat_level = threat_mgmt.get_current_level(threat_file_)

        if current_threat_level >= int(max_threat):
            threat_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            threat_notification = f'[{threat_time}] system at MAX THREAT LEVEL ({max_threat}), possible INCIDENT'

            print(threat_notification)
            socket_.sendall(threat_notification.encode('utf-8'))
        elif current_threat_level >= int(mid_threat):
            threat_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            threat_notification = f'[{threat_time}] system at MEDIUM THREAT LEVEL ({mid_threat})'

            print(threat_notification)
            socket_.sendall(threat_notification.encode('utf-8'))

    def send_notif(self, notification):
        socket_.sendall(notification.encode("utf-8"))


def start_watcher(directories, socket, threat_file, threat_max, threat_mid, threat_default):
    # Assign globals to be used, should prolly fix this eventually
    global socket_, threat_file_, max_threat, mid_threat, default_threat
    socket_ = socket
    threat_file_ = threat_file
    max_threat = threat_max
    mid_threat = threat_mid
    default_threat = threat_default

    watch_manager = pyinotify.WatchManager()
    mask = pyinotify.IN_DELETE | pyinotify.IN_CLOSE_WRITE
    
    notifier = pyinotify.ThreadedNotifier(watch_manager, EventHandler())

    # Iterate over given directory dict
    for key, dir in directories.items():
        watch_manager.add_watch(dir, mask, rec=True)

    notifier.start()
