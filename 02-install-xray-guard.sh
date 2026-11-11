#!/usr/bin/env bash
set -Eeuo pipefail
[[ $(id -u) -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
command -v nft >/dev/null || { echo 'nft is missing' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'python3 is missing' >&2; exit 1; }
command -v systemctl >/dev/null || { echo 'systemctl is missing' >&2; exit 1; }
LOG=/usr/local/x-ui/access.log
[[ -f "$LOG" ]] || { echo "ERROR: $LOG missing; enable Xray access log in 3x-ui first" >&2; exit 1; }
if nft list table inet xray_guard >/dev/null 2>&1; then
  echo 'ERROR: old xray_guard table exists. Run 01-clean-xray-guard.sh first.' >&2; exit 1
fi
TMP_RULES=$(mktemp)
trap 'rm -f "$TMP_RULES"' EXIT
cat > "$TMP_RULES" <<'NFT_RULES'
table inet xray_guard {
    set trusted4 {
        type ipv4_addr
        flags timeout
        timeout 6h
        size 65535
    }
    set seen4 {
        type ipv4_addr
        flags dynamic
        size 65535
    }
    set pending4 {
        type ipv4_addr
        flags dynamic,timeout
        timeout 5m
        size 65535
    }
    set unknown_connections4 {
        type ipv4_addr
        flags dynamic
        size 65535
    }
    chain input {
        type filter hook input priority -10; policy accept;
        meta nfproto ipv4 tcp dport 443 jump check443_v4
    }
    chain check443_v4 {
        counter
        ip saddr @trusted4 return
        ip saddr @seen4 ip saddr != @pending4 counter drop
        ct state new add @unknown_connections4 { ip saddr ct count over 60 } counter drop
        ct state new meter new_connections4 { ip saddr limit rate over 15/second burst 40 packets } counter drop
        ct state new ip saddr != @seen4 add @pending4 { ip saddr timeout 5m }
        ct state new add @seen4 { ip saddr }
    }
}
NFT_RULES
# Preflight syntax validation against clean state; the installer will not
# overwrite an existing guard. No other nftables tables are modified.
nft -c -f "$TMP_RULES"
install -m 0644 "$TMP_RULES" /root/xray-guard.nft
cat > /usr/local/sbin/xray-guard-load.sh <<'LOADER'
#!/bin/sh
set -eu
if nft list table inet xray_guard >/dev/null 2>&1; then
    exit 0
fi
nft -f /root/xray-guard.nft
LOADER
chmod 755 /usr/local/sbin/xray-guard-load.sh

cat > /usr/local/bin/xray-trust-watch.py <<'PYTHON'
#!/usr/bin/env python3
"""Follow only NEW Xray access log lines; trust authenticated inbound-443 IPv4s."""
import ipaddress
import os
import re
import subprocess
import sys
import time

LOG = '/usr/local/x-ui/access.log'
PATTERN = re.compile(
    r'\bfrom (?:tcp:)?(\d{1,3}(?:\.\d{1,3}){3}):\d+ '
    r'accepted .*?\[inbound-443(?:\s|\])'
    r'.*?\]\s+email:\s+(\S+)'
)
# Throttle repeated nft calls, but always check membership again when the
# previous successful update is older than this interval.
last_success = {}
CHECK_INTERVAL = 60
REFRESH_INTERVAL = 1800

def nft(*args, script=None):
    return subprocess.run(['nft', *args], input=script, text=True,
                          capture_output=True, timeout=10)

def trust(ip):
    now = time.monotonic()
    last = last_success.get(ip)
    if last is not None and now - last < CHECK_INTERVAL:
        return
    existing = nft('get', 'element', 'inet', 'xray_guard', 'trusted4', '{', ip, '}')
    if existing.returncode == 0 and last is not None and now - last < REFRESH_INTERVAL:
        last_success[ip] = now if now - last < CHECK_INTERVAL else last
        return
    # Refresh existing element with atomic delete/add transaction; if a concurrent
    # change occurs, retry a plain add. Errors are logged, not swallowed.
    add = f'add element inet xray_guard trusted4 {{ {ip} timeout 6h }}\n'
    script = (f'delete element inet xray_guard trusted4 {{ {ip} }}\n' + add
              if existing.returncode == 0 else add)
    result = nft('-f', '-', script=script)
    if result.returncode != 0:
        result = nft('-f', '-', script=add)
    if result.returncode != 0:
        print(f'ERROR trusting {ip}: {result.stderr.strip()}', flush=True)
        return
    last_success[ip] = now
    print(f'Trusted {ip} for 6h', flush=True)

def process(line):
    match = PATTERN.search(line)
    if not match:
        return
    ip, email = match.groups()
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_global:
        return
    try:
        trust(ip)
    except Exception as exc:
        print(f'ERROR processing {ip}: {exc}', flush=True)

def follow():
    # Read from EOF at startup, never trust historical access records.
    handle = None
    inode = None
    while True:
        try:
            st = os.stat(LOG)
            if handle is None or inode != (st.st_dev, st.st_ino):
                if handle is not None:
                    handle.close()
                handle = open(LOG, 'r', encoding='utf-8', errors='replace')
                inode = (st.st_dev, st.st_ino)
                handle.seek(0, os.SEEK_END)
                print(f'Watching {LOG} (new entries only)', flush=True)
            elif st.st_size < handle.tell():
                handle.seek(0)
                print('Log truncated; following from start', flush=True)
            line = handle.readline()
            if line:
                process(line)
            else:
                time.sleep(0.2)
        except (OSError, ValueError) as exc:
            print(f'ERROR following log: {exc}', flush=True)
            if handle:
                handle.close()
            handle, inode = None, None
            time.sleep(2)

if __name__ == '__main__':
    follow()
PYTHON
chmod 755 /usr/local/bin/xray-trust-watch.py

cat > /usr/local/sbin/xray-guard-cleanup.sh <<'CLEAN'
#!/bin/sh
set -eu
# Atomically clear only the temporary unknown-IP sets.
nft -f - <<'NFT'
flush set inet xray_guard seen4
flush set inet xray_guard pending4
flush set inet xray_guard unknown_connections4
NFT
logger -t xray-guard 'Daily unknown-IP sets cleanup completed'
CLEAN
chmod 755 /usr/local/sbin/xray-guard-cleanup.sh

cat > /etc/systemd/system/xray-guard.service <<'UNIT'
[Unit]
Description=Load xray-guard nftables rules
After=network-pre.target
Before=xray-trust-watch.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/xray-guard-load.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/xray-trust-watch.service <<'UNIT'
[Unit]
Description=Trust successfully authenticated Xray client IPs
Requires=xray-guard.service
After=xray-guard.service x-ui.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 -u /usr/local/bin/xray-trust-watch.py
Restart=always
RestartSec=3
User=root
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/xray-guard-cleanup.service <<'UNIT'
[Unit]
Description=Daily cleanup of unknown Xray IPs
Requires=xray-guard.service
After=xray-guard.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/xray-guard-cleanup.sh
UNIT
cat > /etc/systemd/system/xray-guard-cleanup.timer <<'UNIT'
[Unit]
Description=Clean Xray unknown IP sets at 04:00 UTC

[Timer]
OnCalendar=*-*-* 04:00:00 UTC
Persistent=false
AccuracySec=1min

[Install]
WantedBy=timers.target
UNIT

# Preserve Xray access.log and system journals. The watcher follows new entries
# from EOF; deleting historical logs is unnecessary and harms diagnostics.

systemctl daemon-reload
# Make sure the guard exists before starting the watcher.
systemctl enable --now xray-guard.service
systemctl enable --now xray-trust-watch.service
systemctl enable --now xray-guard-cleanup.timer

# Remove old guard journal records only where journald supports per-unit
# vacuuming? It does not. Do NOT vacuum global journal or affect unrelated services.

echo
echo 'Installation completed.'
echo 'NOTE: new IPs have a fresh 5-minute trial; no IP is pre-trusted.'
echo 'Check log events: journalctl -fu xray-trust-watch.service'
echo 'Check whitelist: nft list set inet xray_guard trusted4'
echo 'Check timer: systemctl list-timers --all | grep xray-guard'
echo 'If access.log does not get NEW accepted lines, verify access logging in 3x-ui.'
