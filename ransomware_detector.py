import time
import math
from collections import Counter, deque
import os
import csv
from termcolor import colored
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

def calculate_entropy(file_path, max_bytes=4096):
    try:
        size = os.path.getsize(file_path)
        if size == 0:
            return 0.0
        with open(file_path, 'rb') as f:
            data = f.read(min(max_bytes, size))
        if not data:
            return 0.0
        counter = Counter(data)
        length = len(data)
        entropy = -sum((count / length) * math.log2(count / length) for count in counter.values() if count > 0)
        return max(0.0, round(entropy, 2))
    except Exception:
        return 0.0


class RansomwareFileHandler(FileSystemEventHandler):

    IGNORED_PREFIXES = ('.', '#', '__')
    IGNORED_SUFFIXES = ('.swp', '.swx', '~', '.save', '.lock', '.tmp', '.bak')

    def __init__(self, csv_file='ransomware_events.csv'):
        self.created_events = deque(maxlen=1000)
        self.modified_events = deque(maxlen=1000)
        self.deleted_events = deque(maxlen=1000)
        self.renamed_events = deque(maxlen=1000)
        self.high_entropy_count = 0
        self.active_high_entropy_files = set()
        self.extensions_last_10s = deque(maxlen=1000)  # for unique extensions
        self.csv_file = csv_file
        # Create CSV headers if file doesn't exist
        if not os.path.exists(csv_file):
            with open(csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'type', 'created_10s', 'modified_10s', 'deleted_10s', 'renamed_10s',
                                 'unique_extensions_10s', 'high_entropy_total', 'active_high_entropy', 'details'])

    def should_ignore(self, path_str):
        filename = os.path.basename(path_str)
        if filename.startswith(self.IGNORED_PREFIXES): return True
        if any(filename.endswith(s) for s in self.IGNORED_SUFFIXES): return True
        return False

    def _record_event(self, queue):
        queue.append(time.time())

    def _count_last_10s(self, queue):
        now = time.time()
        return sum(1 for t in queue if now - t <= 10)

    def _get_unique_extensions_last_10s(self):
        now = time.time()
        recent_exts = set()
        for t, ext in self.extensions_last_10s:
            if now - t <= 10:
                recent_exts.add(ext)
        return len(recent_exts)

    def _log_to_csv(self, event_type, details=''):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        row = [
            timestamp,
            event_type,
            self._count_last_10s(self.created_events),
            self._count_last_10s(self.modified_events),
            self._count_last_10s(self.deleted_events),
            self._count_last_10s(self.renamed_events),
            self._get_unique_extensions_last_10s(),
            self.high_entropy_count,
            len(self.active_high_entropy_files),
            details
        ]
        with open(self.csv_file, 'a', newline='') as f:
            csv.writer(f).writerow(row)

    def on_created(self, event):
        self._record_event(self.created_events)
        if event.is_directory:
            print(colored(f"[DIR CREATED] {event.src_path}", 'cyan'))
            return

        entropy = calculate_entropy(event.src_path)
        ext = os.path.splitext(event.src_path)[1].lower() or '.noext'
        self.extensions_last_10s.append((time.time(), ext))

        if entropy > 7.0:
            self.high_entropy_count += 1
            self.active_high_entropy_files.add(event.src_path)
            self._log_to_csv('HIGH_ENTROPY_CREATE', f"{event.src_path} Entropy:{entropy:.2f}")

        if self.should_ignore(event.src_path): return
        if entropy < 0.5: return

        size = os.path.getsize(event.src_path) if os.path.exists(event.src_path) else 0
        print(f"[CREATED]   {event.src_path: <70}  Size: {size:>6} B   Entropy: {entropy: >5.2f}")

    def on_modified(self, event):
        self._record_event(self.modified_events)
        if event.is_directory: return

        entropy = calculate_entropy(event.src_path)
        ext = os.path.splitext(event.src_path)[1].lower() or '.noext'
        self.extensions_last_10s.append((time.time(), ext))

        if entropy > 7.0:
            if event.src_path not in self.active_high_entropy_files:
                self.high_entropy_count += 1
            self.active_high_entropy_files.add(event.src_path)
            self._log_to_csv('HIGH_ENTROPY_MODIFY', f"{event.src_path} Entropy:{entropy:.2f}")

        if self.should_ignore(event.src_path): return
        if entropy < 0.5: return

        size = os.path.getsize(event.src_path) if os.path.exists(event.src_path) else 0
        print(f"[MODIFIED]  {event.src_path: <70}  Size: {size:>6} B   Entropy: {entropy: >5.2f}")

    def on_deleted(self, event):
        self._record_event(self.deleted_events)
        self.active_high_entropy_files.discard(event.src_path)
        print(colored(f"[DELETED]   {event.src_path}", 'yellow'))

    def on_moved(self, event):
        self._record_event(self.renamed_events)
        if event.is_directory: return

        dest_filename = os.path.basename(event.dest_path).lower()
        suspicious_exts = [
            '.locked', '.crypt', '.encrypted', '.pay', '.bitcoin', '.ransom',
            '.wncry', '.ryuk', '.conti', '.locky', '.svchost', '.random'
        ]

        if any(dest_filename.endswith(ext) for ext in suspicious_exts):
            print(colored(f"[SUSPICIOUS RENAME] {event.src_path} → {event.dest_path}", 'red'))
            self._log_to_csv('SUSPICIOUS_RENAME', f"{event.src_path} → {event.dest_path}")
        else:
            print(f"[RENAMED]   {event.src_path}  →  {event.dest_path}")

        if event.src_path in self.active_high_entropy_files:
            self.active_high_entropy_files.discard(event.src_path)
            self.active_high_entropy_files.add(event.dest_path)

    def print_summary(self):
        c = self._count_last_10s(self.created_events)
        m = self._count_last_10s(self.modified_events)
        d = self._count_last_10s(self.deleted_events)
        r = self._count_last_10s(self.renamed_events)
        active_he = len(self.active_high_entropy_files)
        total_ops = c + m + d + r
        unique_ext = self._get_unique_extensions_last_10s()

        summary_line = f"[SUMMARY 10s]  Created: {c:>3}   Modified: {m:>3}   Deleted: {d:>3}   Renamed: {r:>3}   High-entropy: {self.high_entropy_count:>3}   Active High-entropy: {active_he:>3}   Unique Exts: {unique_ext:>2}"
        print(colored(summary_line, 'green'))

        self._log_to_csv('SUMMARY', f"C:{c} M:{m} D:{d} R:{r} HE:{self.high_entropy_count} ActiveHE:{active_he} UniqueExts:{unique_ext}")

        # Alert thresholds
        if r > 10:
            print(colored("HIGH RISK! Possible ransomware rename attack", 'red', attrs=['bold']))
            self._log_to_csv('ALERT', 'Possible ransomware rename attack')
        if d > 10:
            print(colored("HIGH RISK! Mass deletion detected", 'red', attrs=['bold']))
            self._log_to_csv('ALERT', 'Mass deletion detected')
        if self.high_entropy_count > 5:
            print(colored("HIGH RISK! Encryption detected", 'red', attrs=['bold']))
            self._log_to_csv('ALERT', 'Encryption detected')
        if total_ops > 50:
            print(colored("HIGH RISK! Massive file activity detected", 'red', attrs=['bold']))
            self._log_to_csv('ALERT', 'Massive file activity detected')


if __name__ == "__main__":
    print("=== RANSOMWARE FILE FEATURES DETECTOR ===")
    print("With CSV logging, unique extensions count, and color alerts\n")

    username = input("Enter your username: ").strip()
    if not username:
        print("No username → exit")
        exit(1)

    watch_folder = f"/home/{username}"

    print(f"\nWatching: {watch_folder} (recursive)")
    print("Data saved to ransomware_events.csv")
    print("Press Ctrl+C to stop\n")

    event_handler = RansomwareFileHandler()
    observer = Observer()
    observer.schedule(event_handler, watch_folder, recursive=True)
    observer.start()

    last_summary = time.time()

    try:
        while True:
            time.sleep(1)
            now = time.time()
            if now - last_summary >= 10:
                event_handler.print_summary()
                last_summary = now
    except KeyboardInterrupt:
        print("\nStopping watcher...")
        observer.stop()
    observer.join()
    print("Watcher stopped.")
    print("Check ransomware_events.csv for all logged data")
