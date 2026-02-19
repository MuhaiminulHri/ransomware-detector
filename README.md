
### 2. Detailed README (2-page version)  
Save this as `README-detailed.md`

```markdown
# Ransomware File Features Detector – Capstone Project

## Overview
This Python tool monitors the file system in real time to detect signs of ransomware activity.  
It focuses on **file features** — the most critical signals for early ransomware detection.

Key capabilities:
- Real-time monitoring of file create/modify/delete/rename events
- Entropy calculation to identify encrypted (high-randomness) files
- Suspicious rename detection (e.g. .locked, .crypt, .encrypted extensions)
- Operation counters every 10 seconds (volume & speed)
- Cumulative + active high-entropy tracking
- Visual alerts for high-risk behavior
- CSV logging for analysis and ML training

## Features in Detail

### 1. File System Monitoring
- Watches entire `/home/<username>` recursively using `watchdog`
- Captures every:
  - File creation (`[CREATED]`)
  - Modification (`[MODIFIED]`)
  - Deletion (`[DELETED]`)
  - Rename/move (`[RENAMED]` or `[SUSPICIOUS RENAME]`)

### 2. Entropy-Based Encryption Detection
- Computes Shannon entropy on first 4KB of each created/modified file
- Threshold > 7.0 → considered "encrypted-like"
- `High-entropy`: total count ever seen (cumulative)
- `Active High-entropy`: count of currently existing high-entropy files (drops on delete)

### 3. Suspicious Rename Detection
- Flags renames ending with known ransomware extensions:
  .locked .crypt .encrypted .pay .bitcoin .ransom .wncry .ryuk .conti .locky .svchost .random
- Prints in red: `[SUSPICIOUS RENAME] old → new`

### 4. Real-Time Counters & Alerts (every 10 seconds)
- Counts: created, modified, deleted, renamed in last 10s
- Alerts (red + bold) when:
  - Renamed > 10 → "HIGH RISK! Possible ransomware rename attack"
  - Deleted > 10 → "HIGH RISK! Mass deletion detected"
  - High-entropy > 5 → "HIGH RISK! Encryption detected"
  - Total operations > 50 → "HIGH RISK! Massive file activity detected"

### 5. Data Logging
- Saves to `ransomware_events.csv`
- Columns: timestamp, type (SUMMARY/ALERT/HIGH_ENTROPY_CREATE/etc.), all counters, unique extensions (future), high_entropy_total, active_high_entropy, details
- Easy to open in Excel / import to Python/Pandas

### 6. Visual Terminal Output
- Green summaries
- Red alerts
- Yellow deletions
- Cyan directory events

## How to Run

1. Install required packages (once):
   ```bash
   
- pip install watchdog
- Bash
- pip install psutil

## How to Make python file
nano  ransomware_detector.py

## How to Run

python ransomware_detector.py


