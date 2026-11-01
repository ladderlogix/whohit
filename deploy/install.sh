#!/usr/bin/env bash
# Install or update whoHit on the box. Run as root from the unpacked source tree:
#   sudo bash deploy/install.sh
set -euo pipefail
cd "$(dirname "$0")/.."

command -v nft >/dev/null && command -v tcpdump >/dev/null || apt-get install -y -q nftables tcpdump
command -v sqlite3 >/dev/null || apt-get install -y -q sqlite3   # for ad-hoc queries

id whohit >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin whohit

install -d -m 755 /opt/whohit /opt/whohit/static
install -m 644 whohit/*.py /opt/whohit/
install -m 644 whohit/static/index.html /opt/whohit/static/

install -d -m 750 -o root -g whohit /etc/whohit
install -m 644 deploy/redirect.nft /etc/whohit/redirect.nft
[ -f /etc/whohit/watch.txt ] || install -m 644 deploy/watch.txt /etc/whohit/watch.txt   # keep local edits
if [ ! -f /etc/whohit/tls.key ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=localhost" \
        -keyout /etc/whohit/tls.key -out /etc/whohit/tls.crt 2>/dev/null
    chgrp whohit /etc/whohit/tls.key /etc/whohit/tls.crt
    chmod 640 /etc/whohit/tls.key
    chmod 644 /etc/whohit/tls.crt
fi

install -m 644 deploy/whohit-*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable whohit-sniffer whohit-listener whohit-dashboard whohit-enrich
systemctl restart whohit-sniffer whohit-listener whohit-dashboard whohit-enrich
sleep 2
systemctl --no-pager --lines=3 status whohit-sniffer whohit-listener whohit-dashboard whohit-enrich | grep -E "●|Active:|whohit\["
