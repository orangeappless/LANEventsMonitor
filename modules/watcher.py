import pyinotify
import socket
from datetime import datetime


class EventHandler(pyinotify.ProcessEvent):
    def process_IN_CREATE(self, event):
        # Creation in directory
        notification = f"Created: {event.pathname}"
        print(notification)
        self.send_notif(notification)

    def process_IN_DELETE(self, event):
        # Deletion in directory
        notification = f"Deleted: {event.pathname}"
        print(notification)
        self.send_notif(notification)

    def process_IN_CLOSE_WRITE(self, event):
        # Change in file in directory
        notification = f"Modified: {event.pathname}"
        print(notification)
        self.send_notif(notification)

    def send_notif(self, notification):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data = f"[{current_time}] {notification}"

        socket_.send(data.encode("utf-8"))


def start_watcher(directories, socket):
    # Socket object, used to send notifications to server
    global socket_
    socket_ = socket

    watch_manager = pyinotify.WatchManager()
    mask = pyinotify.IN_CREATE | pyinotify.IN_DELETE | pyinotify.IN_CLOSE_WRITE
    
    notifier = pyinotify.ThreadedNotifier(watch_manager, EventHandler())

    # Iterate over given directory dict
    for key, dir in directories.items():
        watch_manager.add_watch(dir, mask, rec=True)

    notifier.start()
    print("Notifier started")
