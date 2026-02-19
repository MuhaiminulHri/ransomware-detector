# Ransomware File Features Detector  
**My Part in the AI-Based Ransomware IDPS Capstone Project**

**Student:** Muhaiminul  
**Group:** Dania, Kwame, Sharan, Wyzzman, Imad  
**Date:** February 19, 2026

## My Role
From the meeting on Feb 2 and the milestones plan, my job is **File Features** — the main way to spot ransomware by watching how files are being changed.  
This matches the architecture diagram (Monitoring Agent → Feature Engineering → ML Engine) and Milestones 2 & 3.

My module:
- Watches file events (create, modify, delete, rename) in real time
- Calculates entropy to detect encrypted files
- Counts operations to catch fast attacks
- Flags suspicious renames
- Gives alerts when things look dangerous
- Saves data for the ML team (Kwame & Sharan)

## What It Does
- Monitors `/home/<username>` (recursive) using Watchdog
- Detects high-entropy files (>7.5 = likely encrypted)
- Tracks cumulative (total seen) and active (still existing) high-entropy files
- Counts created/modified/deleted/renamed every 10 seconds
- Shows unique file extensions touched in last 10s
- Flags renames to .locked, .crypt, .encrypted, .pay, .bitcoin, .ransom, etc.
- Shows process name/PID (using psutil) for each event
- Prints HIGH RISK alerts in red when:
  - Renamed > 10 in 10s
  - Deleted > 10 in 10s
  - High-entropy > 5
  - Total ops > 50 in 10s
- Saves summaries + alerts to `ransomware_events.csv` **every 60 seconds** (to save storage/speed)
- Provides feature vectors for ML Engine

## How to Run
1. Install libraries (once):
   ```bash
   pip install watchdog psutil pandas numpy termcolor

## Run the script:
python ransomware_detector.py
Enter your username (e.g. kali)

Test:
Fast renames:
Bashfor 
i in {1..15}; do touch f$i.pdf; mv f$i.pdf f$i.pdf.locked; done

Encrypted-like files:
Bashfor 
i in {1..7}; do head -c 20000 /dev/urandom > rand$i.bin; done
