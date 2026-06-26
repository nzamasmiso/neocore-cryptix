#!/bin/bash
# MemScanner Linux Agent v2 - T1055.003 Detection

REPORT_DIR='migration_alerts'
mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT="$REPORT_DIR/migration_alert_$TIMESTAMP.txt"

echo "===Meterpreter Migration Detection - $TIMESTAMP===" | tee "$REPORT"
echo "" >> "$REPORT"

# 1. Parent PID = 1 but not init/systemd. Common after process hollowing/migration
echo "[*] Checking for parent-child PID anomalies..." | tee -a "$REPORT"
ps -eo pid,ppid,cmd --no-headers | awk '
$2 == 1 && $1!= 1 && $0 ~ /(bash|python|powershell|sh)$/ {
    print "SUSPICIOUS: PID="$1" PPID=1 CMD="$0
}' >> "$REPORT"
echo "" >> "$REPORT"

# 2. RWX memory regions - shellcode needs this [5]
echo "[*] Checking for RWX memory regions - injection indicator..." | tee -a "$REPORT"
for pid in $(ps -eo pid --no-headers); do
    if [ -r "/proc/$pid/maps" ]; then
        rwx_count=$(grep -c "rwxp" "/proc/$pid/maps" 2>/dev/null) # rwxp = read+write+exec+private
        if [ "$rwx_count" -gt 0 ]; then # Fix: was gt 2
            cmd=$(ps -p "$pid" -o cmd --no-headers 2>/dev/null) # Fix: was cmd[ps
            echo "ALERT: PID $pid has $rwx_count RWX region(s). CMD: $cmd" >> "$REPORT"
        fi
    fi
done
echo "" >> "$REPORT"

# 3. Recently spawned processes from common target names. Use elapsed time, not date regex
echo "[*] Checking for short-lived processes from common targets..." | tee -a "$REPORT"
ps -eo pid,ppid,cmd,etimes --no-headers | awk '
$2!= 1 && $4 < 300 && $3 ~ /(explorer|svchost|winlogon|bash|sshd)$/ {
    print "NEW: PID="$1" PPID="$2" AGE="$4"s CMD="$3
}' >> "$REPORT" # etimes < 300 = spawned in last 5 min
echo "" >> "$REPORT"

# 4. Network processes with PPID=1. Hidden C2 after migration
echo "[*] Checking for network processes with hidden parent..." | tee -a "$REPORT"
ss -tnp state established 2>/dev/null | awk 'NR>1 {print $0}' | while read -r line; do
    pid=$(echo "$line" | grep -oP 'pid=\K[0-9]+')
    if [ -n "$pid" ]; then
        ppid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
        cmd=$(ps -o cmd= -p "$pid" 2>/dev/null)
        if [ "$ppid" == "1" ]; then
            echo "ALERT: Network PID $pid has PPID=1. CMD: $cmd" >> "$REPORT"
        fi
    fi
done

echo "" >> "$REPORT"
echo "[*] Scan Complete" >> "$REPORT"
echo "Report saved: $REPORT"
