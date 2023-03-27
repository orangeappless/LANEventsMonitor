import pyinotify
import socket
from datetime import datetime


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

    def send_notif(self, notification):
        socket_.sendall(notification.encode("utf-8"))


def start_watcher(directories, socket):
    # Socket object, used to send notifications to server
    global socket_
    socket_ = socket

    watch_manager = pyinotify.WatchManager()
    mask = pyinotify.IN_DELETE | pyinotify.IN_CLOSE_WRITE
    
    notifier = pyinotify.ThreadedNotifier(watch_manager, EventHandler())

    # Iterate over given directory dict
    for key, dir in directories.items():
        watch_manager.add_watch(dir, mask, rec=True)

    notifier.start()
