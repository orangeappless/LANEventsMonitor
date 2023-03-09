import pyinotify


class EventHandler(pyinotify.ProcessEvent):
    def process_IN_CREATE(self, event):
        # Creation in directory
        print("Created:", event.pathname)

    def process_IN_DELETE(self, event):
        # Deletion in directory
        print("Deleted:", event.pathname)

    def process_IN_CLOSE_WRITE(self, event):
        # Change in file in directory
        print("Modified:", event.pathname)


def start_watcher(directories):
    watch_manager = pyinotify.WatchManager()
    mask = pyinotify.IN_CREATE | pyinotify.IN_DELETE | pyinotify.IN_MODIFY | pyinotify.IN_CLOSE_WRITE | pyinotify.IN_CLOSE_NOWRITE
    
    notifier = pyinotify.ThreadedNotifier(watch_manager, EventHandler())

    # Iterate over given directory dict
    for key, dir in directories.items():
        watch_manager.add_watch(dir, mask, rec=True)

    notifier.start()
    print("Notifier started")
