import time
import math
from collections import Counter, deque
import os
import csv
import psutil
import pandas as pd
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configuration
CONFIG = {
    "entropy_threshold": 7.5,
    "rename_threshold": 10,
    "delete_threshold": 10,
    "high_entropy_threshold": 5,
    "total_ops_threshold": 50,
    "summary_interval": 10,          # Terminal summary every 10 seconds
    "csv_interval": 60,              # CSV write every 60 seconds (less storage)
    "csv_file": 'ransomware_events.csv'
}

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

    def __init__(self):
        self.created_events = deque(maxlen=1000)
        self.modified_events = deque(maxlen=1000)
        self.deleted_events = deque(maxlen=1000)
        self.renamed_events = deque(maxlen=1000)
        self.high_entropy_count = 0
        self.active_high_entropy_files = set()
        self.extensions_last_10s = deque(maxlen=1000)
        self.feature_vectors = []  # For ML engine integration

        # CSV setup (headers only once)
        if not os.path.exists(CONFIG['csv_file']):
            with open(CONFIG['csv_file'], 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'type', 'created_10s', 'modified_10s', 'deleted_10s', 'renamed_10s',
                                 'unique_exts_10s', 'high_entropy_total', 'active_high_entropy', 'details'])

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
        with open(CONFIG['csv_file'], 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(row)

    def _get_process_info(self, event):
        try:
            pids = psutil.pids()
            for pid in pids:
                p = psutil.Process(pid)
                if event.src_path in [f.path for f in p.open_files()]:
                    return p.name(), p.pid
        except Exception:
            return None, None
        return None, None

    def on_created(self, event):
        self._record_event(self.created_events)
        if event.is_directory:
            print(f"[DIR CREATED] {event.src_path}")
            return

        entropy = calculate_entropy(event.src_path)
        ext = os.path.splitext(event.src_path)[1].lower() or '.noext'
        self.extensions_last_10s.append((time.time(), ext))

        if entropy > CONFIG['entropy_threshold']:
            self.high_entropy_count += 1
            self.active_high_entropy_files.add(event.src_path)
            self._log_to_csv('HIGH_ENTROPY_CREATE', f"{event.src_path} Entropy:{entropy:.2f}")

        if self.should_ignore(event.src_path): return
        if entropy < 0.5: return

        size = os.path.getsize(event.src_path) if os.path.exists(event.src_path) else 0
        process_name, pid = self._get_process_info(event)
        print(f"[CREATED] {event.src_path: <70} Size: {size:>6} B Entropy: {entropy: >5.2f} Process: {process_name} (PID:{pid})")

        # Save feature vector for ML
        self.feature_vectors.append({
            'event_type': 'create',
            'entropy': entropy,
            'size': size,
            'extension': ext,
            'process': process_name
        })

    def on_modified(self, event):
        self._record_event(self.modified_events)
        if event.is_directory: return

        entropy = calculate_entropy(event.src_path)
        ext = os.path.splitext(event.src_path)[1].lower() or '.noext'
        self.extensions_last_10s.append((time.time(), ext))

        if entropy > CONFIG['entropy_threshold']:
            if event.src_path not in self.active_high_entropy_files:
                self.high_entropy_count += 1
            self.active_high_entropy_files.add(event.src_path)
            self._log_to_csv('HIGH_ENTROPY_MODIFY', f"{event.src_path} Entropy:{entropy:.2f}")

        if self.should_ignore(event.src_path): return
        if entropy < 0.5: return

        size = os.path.getsize(event.src_path) if os.path.exists(event.src_path) else 0
        process_name, pid = self._get_process_info(event)
        print(f"[MODIFIED] {event.src_path: <70} Size: {size:>6} B Entropy: {entropy: >5.2f} Process: {process_name} (PID:{pid})")

        # Save feature vector
        self.feature_vectors.append({
            'event_type': 'modify',
            'entropy': entropy,
            'size': size,
            'extension': ext,
            'process': process_name
        })

    def on_deleted(self, event):
        self._record_event(self.deleted_events)
        self.active_high_entropy_files.discard(event.src_path)
        process_name, pid = self._get_process_info(event)
        print(f"[DELETED] {event.src_path} Process: {process_name} (PID:{pid})")

        # Save feature vector
        self.feature_vectors.append({
            'event_type': 'delete',
            'process': process_name
        })

    def on_moved(self, event):
        self._record_event(self.renamed_events)
        if event.is_directory: return

        dest_filename = os.path.basename(event.dest_path).lower()
        suspicious_exts = [
            '.locked', '.crypt', '.encrypted', '.pay', '.bitcoin', '.ransom',
            '.wncry', '.ryuk', '.conti', '.locky', '.svchost', '.random'
        ]

        if any(dest_filename.endswith(ext) for ext in suspicious_exts):
            print(f"[SUSPICIOUS RENAME] {event.src_path} → {event.dest_path}")
            self._log_to_csv('SUSPICIOUS_RENAME', f"{event.src_path} → {event.dest_path}")
        else:
            print(f"[RENAMED] {event.src_path} → {event.dest_path}")

        if event.src_path in self.active_high_entropy_files:
            self.active_high_entropy_files.discard(event.src_path)
            self.active_high_entropy_files.add(event.dest_path)

        # Save feature vector
        self.feature_vectors.append({
            'event_type': 'rename',
            'old_ext': os.path.splitext(event.src_path)[1].lower(),
            'new_ext': os.path.splitext(event.dest_path)[1].lower()
        })

    def print_summary(self):
        c = self._count_last_10s(self.created_events)
        m = self._count_last_10s(self.modified_events)
        d = self._count_last_10s(self.deleted_events)
        r = self._count_last_10s(self.renamed_events)
        active_he = len(self.active_high_entropy_files)

        print(f"[SUMMARY 10s] Created: {c:>3} Modified: {m:>3} Deleted: {d:>3} Renamed: {r:>3} High-entropy: {self.high_entropy_count:>3} Active High-entropy: {active_he:>3}")

        # Alert thresholds
        if r > CONFIG['rename_threshold']:
            print("HIGH RISK! Possible ransomware rename attack")
        if d > CONFIG['delete_threshold']:
            print("HIGH RISK! Mass deletion detected")
        if self.high_entropy_count > CONFIG['high_entropy_threshold']:
            print("HIGH RISK! Encryption detected")
        if (c + m + d + r) > CONFIG['total_ops_threshold']:
            print("HIGH RISK! Massive file activity")

    def get_feature_vector(self):
        # Output standardized feature vector for ML engine
        return pd.DataFrame(self.feature_vectors).to_numpy()  # or save to pickle for XGBoost


if __name__ == "__main__":
    print("=== RANSOMWARE FILE FEATURES DETECTOR ===")
    print("File Features module for IDPS Capstone Project\n")

    username = input("Enter your username: ").strip()
    if not username:
        print("No username → exit")
        exit(1)

    watch_folder = f"/home/{username}"

    print(f"\nWatching: {watch_folder} (recursive)")
    print("Press Ctrl+C to stop\n")

    event_handler = RansomwareFileHandler()
    observer = Observer()
    observer.schedule(event_handler, watch_folder, recursive=True)
    observer.start()

    last_summary = time.time()
    last_csv_write = time.time()

    try:
        while True:
            time.sleep(1)
            now = time.time()

            # Terminal summary every 10 seconds
            if now - last_summary >= CONFIG['summary_interval']:
                event_handler.print_summary()
                last_summary = now

            # CSV write every 60 seconds
            if now - last_csv_write >= CONFIG['csv_interval']:
                event_handler._log_to_csv('SUMMARY', f"Periodic save - C:{event_handler._count_last_10s(event_handler.created_events)} M:{event_handler._count_last_10s(event_handler.modified_events)} D:{event_handler._count_last_10s(event_handler.deleted_events)} R:{event_handler._count_last_10s(event_handler.renamed_events)} HE:{event_handler.high_entropy_count} ActiveHE:{len(event_handler.active_high_entropy_files)} UniqueExts:{event_handler._get_unique_extensions_last_10s()}")
                last_csv_write = now

    except KeyboardInterrupt:
        print("\nStopping watcher...")
        observer.stop()
    observer.join()
    print("Watcher stopped.")
    print("Final data saved to ransomware_events.csv")
