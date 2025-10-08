#!/bin/bash

# Timeline Analysis Script
# Creates a timeline of events from forensic evidence

EVIDENCE_DIR="$1"

if [ -z "$EVIDENCE_DIR" ]; then
    echo "Usage: $0 <evidence_directory>"
    exit 1
fi

cd "$EVIDENCE_DIR"

TIMELINE_FILE="timeline_analysis.txt"

echo "FORENSIC TIMELINE ANALYSIS" > "$TIMELINE_FILE"
echo "==========================" >> "$TIMELINE_FILE"
echo "Analysis Date: $(date)" >> "$TIMELINE_FILE"
echo "" >> "$TIMELINE_FILE"

echo "[+] Creating forensic timeline..."

# Parse file modification times
if [ -f "recent_files_1day.txt" ]; then
    echo "RECENT FILE MODIFICATIONS (Last 24 hours):" >> "$TIMELINE_FILE"
    echo "===========================================" >> "$TIMELINE_FILE"
    
    # This would normally be done with more sophisticated tools like log2timeline
    # For demonstration, we'll create a basic timeline
    while IFS= read -r file; do
        if [ -n "$file" ]; then
            echo "FILE: $file" >> "$TIMELINE_FILE"
        fi
    done < "recent_files_1day.txt"
    echo "" >> "$TIMELINE_FILE"
fi

# Parse log entries with timestamps
if [ -f "syslog.txt" ]; then
    echo "SYSTEM LOG TIMELINE:" >> "$TIMELINE_FILE"
    echo "====================" >> "$TIMELINE_FILE"
    
    # Extract recent log entries (last 100 lines as example)
    tail -100 "syslog.txt" >> "$TIMELINE_FILE" 2>/dev/null || true
    echo "" >> "$TIMELINE_FILE"
fi

if [ -f "auth_log.txt" ]; then
    echo "AUTHENTICATION LOG TIMELINE:" >> "$TIMELINE_FILE"
    echo "============================" >> "$TIMELINE_FILE"
    
    # Extract recent auth events
    tail -50 "auth_log.txt" >> "$TIMELINE_FILE" 2>/dev/null || true
    echo "" >> "$TIMELINE_FILE"
fi

echo "Timeline analysis complete: $TIMELINE_FILE"