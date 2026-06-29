#!/usr/bin/env bash
# harden.sh: Host hardening for Trap House honeypot on Hetzner VPS.
# Run as root on a fresh Ubuntu 24.04 or Debian 12 VPS.
#
# What this script does:
# 1. Moves host SSH to port 65022 (frees port 22 for Endlessh tarpit)
# 2. Configures UFW firewall (only honeypot ports open)
# 3. Installs and configures fail2ban
# 4. Enables unattended security upgrades
# 5. Disables root SSH login and password authentication
# 6. Installs Docker and docker-compose-plugin
#
# WARNING: This script changes SSH port. After running, connect with:
#   ssh -p 65022 user@your-vps-ip
#
# Usage: sudo bash harden.sh SSH_USER

set -euo pipefail

SSH_USER="${1:-}"
if [ -z "$SSH_USER" ] || [ "$SSH_USER" = "root" ]; then
  echo "Usage: sudo bash harden.sh SSH_USER"
  echo "SSH_USER must be a non-root user with sudo access."
  exit 1
fi

NEW_SSH_PORT=65022

echo "=== Trap House Host Hardening ==="
echo "SSH user: $SSH_USER"
echo "New SSH port: $NEW_SSH_PORT"
echo ""

# 1. System update
echo "[1/7] Updating system packages..."
apt-get update -qq && apt-get upgrade -y -qq

# 2. Install dependencies
echo "[2/7] Installing required packages..."
apt-get install -y -qq ufw fail2ban unattended-upgrades curl gnupg ca-certificates

# 3. Configure UFW firewall
echo "[3/7] Configuring firewall..."
ufw --force reset
# Allow the new SSH port
ufw allow ${NEW_SSH_PORT}/tcp comment "Host SSH"
# Allow honeypot ports
ufw allow 22/tcp comment "Endlessh tarpit"
ufw allow 2222/tcp comment "Cowrie SSH"
ufw allow 2223/tcp comment "Cowrie Telnet"
ufw allow 80/tcp comment "Deception-gw HTTP"
# Explicitly DENY access to internal services from outside
ufw deny 3000/tcp comment "Grafana (internal only)"
ufw deny 8001/tcp comment "Frontend (internal only)"
ufw --force enable
echo "Firewall rules applied."

# 4. Move SSH to high port and disable root/password login
echo "[4/7] Hardening SSH..."
SSHD_CONFIG="/etc/ssh/sshd_config"
cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.$(date +%s)"

# Change port
sed -i "s/^#\?Port .*/Port ${NEW_SSH_PORT}/" "$SSHD_CONFIG"
# Disable root login
sed -i "s/^#\?PermitRootLogin .*/PermitRootLogin no/" "$SSHD_CONFIG"
# Disable password authentication (require SSH keys)
sed -i "s/^#\?PasswordAuthentication .*/PasswordAuthentication no/" "$SSHD_CONFIG"
# Disable empty passwords
sed -i "s/^#\?PermitEmptyPasswords .*/PermitEmptyPasswords no/" "$SSHD_CONFIG"
# Limit max auth tries
if ! grep -q "MaxAuthTries" "$SSHD_CONFIG"; then
  echo "MaxAuthTries 3" >> "$SSHD_CONFIG"
else
  sed -i "s/^#\?MaxAuthTries .*/MaxAuthTries 3/" "$SSHD_CONFIG"
fi

systemctl restart sshd
echo "SSH moved to port ${NEW_SSH_PORT}. Root login and password auth disabled."

# 5. Configure fail2ban
echo "[5/7] Configuring fail2ban..."
cat > /etc/fail2ban/jail.local << 'FAIL2BAN'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = 65022
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200
FAIL2BAN

systemctl enable fail2ban
systemctl restart fail2ban
echo "fail2ban configured for SSH on port ${NEW_SSH_PORT}."

# 6. Enable unattended security upgrades
echo "[6/7] Enabling unattended security upgrades..."
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'UNATTENDED'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::Automatic-Reboot "false";
UNATTENDED

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'AUTO'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
AUTO

echo "Unattended security upgrades enabled."

# 7. Install Docker
echo "[7/7] Installing Docker..."
if ! command -v docker &> /dev/null; then
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
  usermod -aG docker "$SSH_USER"
  systemctl enable docker
  echo "Docker installed. User '$SSH_USER' added to docker group."
else
  echo "Docker already installed, skipping."
fi

echo ""
echo "=== Hardening Complete ==="
echo ""
echo "IMPORTANT: Test SSH on the new port before closing this session:"
echo "  ssh -p ${NEW_SSH_PORT} ${SSH_USER}@$(hostname -I | awk '{print $1}')"
echo ""
echo "Then deploy Trap House:"
echo "  cd /opt/trap-house"
echo "  cp .env.hetzner.example .env.hetzner"
echo "  # Edit .env.hetzner: set SESSION_SECRET and GRAFANA_ADMIN_PASSWORD"
echo "  docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env.hetzner up -d"
echo ""
echo "Access internal dashboards via SSH tunnel:"
echo "  ssh -p ${NEW_SSH_PORT} -L 8001:localhost:8001 -L 3000:localhost:3000 ${SSH_USER}@your-vps-ip"
echo ""
echo "Then open:"
echo "  http://localhost:8001  (SOC Dashboard)"
echo "  http://localhost:3000  (Grafana)"