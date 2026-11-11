#!/usr/bin/env bash
set -Eeuo pipefail
[[ $(id -u) -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
command -v nft >/dev/null || { echo 'nft is missing' >&2; exit 1; }
# Stop the old guard and any pending rollback before removing rules.
for unit in xray-guard-auto-rollback.timer xray-guard-auto-rollback.service xray-guard-cleanup.timer xray-guard-cleanup.service xray-trust-watch.service xray-guard.service; do
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
done
# Delete ONLY our own nftables tables, not the whole firewall.
for table in xray_guard xray_guard_test; do
    if nft list table inet "$table" >/dev/null 2>&1; then
        nft delete table inet "$table"
    fi
done
rm -f /etc/systemd/system/xray-trust-watch.service /etc/systemd/system/xray-guard.service \
 /etc/systemd/system/xray-guard-cleanup.service /etc/systemd/system/xray-guard-cleanup.timer \
 /etc/systemd/system/xray-guard-auto-rollback.service /etc/systemd/system/xray-guard-auto-rollback.timer
rm -rf /etc/systemd/system/xray-trust-watch.service.d
rm -f /usr/local/bin/xray-trust-watch.py /usr/local/sbin/xray-guard-load.sh /usr/local/sbin/xray-guard-cleanup.sh
rm -f /root/xray-guard.nft /root/xray-guard-apply.nft /root/xray-guard-test.nft \
 /root/xray-guard-rollback.nft /root/xray-guard-rollback.sh /root/xray-guard-deploy.py \
 /root/xray-trusted-before.json
systemctl daemon-reload
systemctl reset-failed xray-guard.service xray-trust-watch.service xray-guard-cleanup.service 2>/dev/null || true
# Never delete /usr/local/x-ui/access.log: it is owned by Xray and used for diagnosis.
# journald is shared; deleting global logs would affect unrelated services.
echo 'Cleanup complete: guard tables, units and scripts removed; Xray, sing-box, SSH and their logs preserved.'
