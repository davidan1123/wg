#!/usr/bin/env bash
# Server bootstrap: update packages, create an SSH user, shell tweaks,
# harden SSH and UFW.
# Run as root:  sudo ./server-harden.sh   (also offered by wg-ubuntu-server-up.sh)
# The script asks for the SSH port, username, password and open ports.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run this as root (sudo bash $0)." >&2
  exit 1
fi

# --- 0. Questions -----------------------------------------------------------
while true; do
  read -rp "SSH port [22222]: " SSH_PORT
  SSH_PORT="${SSH_PORT:-22222}"
  if [[ "$SSH_PORT" =~ ^[0-9]+$ ]] && [ "$SSH_PORT" -ge 1 ] && [ "$SSH_PORT" -le 65535 ]; then
    break
  fi
  echo "Invalid port, enter a number between 1 and 65535."
done

while true; do
  read -rp "SSH username: " SSH_USER
  if [[ "$SSH_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] && [ "$SSH_USER" != "root" ]; then
    break
  fi
  echo "Invalid username (lowercase letters, digits, - or _; not root)."
done

SET_PASS=y
if id "$SSH_USER" &> /dev/null; then
  read -rp "User $SSH_USER exists. Set a new password? [y/N]: " SET_PASS
fi

PASS_HASH=""
if [[ "$SET_PASS" =~ ^[Yy]$ ]]; then
  while true; do
    read -rsp "Password for $SSH_USER: " PASS1; echo
    read -rsp "Repeat password: " PASS2; echo
    if [ -z "$PASS1" ]; then
      echo "Password cannot be empty."
    elif [ "${#PASS1}" -lt 12 ]; then
      echo "Use at least 12 characters."
    elif [ "$PASS1" != "$PASS2" ]; then
      echo "Passwords do not match."
    else
      break
    fi
  done
  # SHA-512 crypt hash; password is passed on stdin, never on the command line.
  PASS_HASH="$(openssl passwd -6 -stdin <<< "$PASS1")"
  unset PASS1 PASS2
fi

echo
echo "Extra ports to open in UFW, space separated (e.g. 80/tcp 443/tcp 5055/tcp)."
read -rp "Leave empty for SSH only: " EXTRA_PORTS
for p in $EXTRA_PORTS; do
  if ! [[ "$p" =~ ^[0-9]+(:[0-9]+)?(/(tcp|udp))?$ ]]; then
    echo "ERROR: invalid port spec '$p'." >&2
    exit 1
  fi
done

echo
echo "SSH port:    $SSH_PORT"
echo "SSH user:    $SSH_USER"
echo "Extra ports: ${EXTRA_PORTS:-none}"
echo "WARNING: existing UFW rules will be reset."
read -rp "Continue? [y/N]: " ok
[[ "$ok" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 1; }

USER_HOME="/home/$SSH_USER"

# --- 1. Packages ------------------------------------------------------------
apt update
DEBIAN_FRONTEND=noninteractive apt full-upgrade -y
apt install -y sudo lsof tcpdump ufw openssl

# --- 2. User + sudo ---------------------------------------------------------
if id "$SSH_USER" &> /dev/null; then
  echo "User $SSH_USER already exists, skipping creation."
else
  useradd -m -s /bin/bash "$SSH_USER"
fi

if [ -n "$PASS_HASH" ]; then
  # -e: the value is already hashed, store it as-is in /etc/shadow.
  echo "$SSH_USER:$PASS_HASH" | chpasswd -e
  unset PASS_HASH
fi

echo "$SSH_USER ALL=(ALL) NOPASSWD: ALL" > "/etc/sudoers.d/$SSH_USER"
chmod 0440 "/etc/sudoers.d/$SSH_USER"
visudo -cf "/etc/sudoers.d/$SSH_USER"

# --- 3. SSH key -------------------------------------------------------------
install -d -m 700 -o "$SSH_USER" -g "$SSH_USER" "$USER_HOME/.ssh"
AUTH_KEYS="$USER_HOME/.ssh/authorized_keys"

if [ ! -s "$AUTH_KEYS" ]; then
  echo
  echo "Paste the public key for $SSH_USER (ssh-ed25519 / ssh-rsa ...)."
  read -rp "Leave empty to copy root's authorized_keys: " PUBKEY
  if [ -n "$PUBKEY" ]; then
    echo "$PUBKEY" > "$AUTH_KEYS"
  elif [ -s /root/.ssh/authorized_keys ]; then
    cp /root/.ssh/authorized_keys "$AUTH_KEYS"
  fi
fi

if [ ! -s "$AUTH_KEYS" ]; then
  echo "ERROR: no SSH key for $SSH_USER. Password login will be disabled," >&2
  echo "so you would be locked out. Aborting before touching SSH." >&2
  exit 1
fi
chown "$SSH_USER:$SSH_USER" "$AUTH_KEYS"
chmod 600 "$AUTH_KEYS"

# --- 4. Shell tweaks --------------------------------------------------------
touch "$USER_HOME/.hushlogin"
if ! grep -q "alias c='clear'" "$USER_HOME/.bashrc" 2> /dev/null; then
  cat >> "$USER_HOME/.bashrc" << 'EOF'
alias c='clear'
alias h='history'
export PS1="\[$(tput setaf 6; tput rev; tput bold)\]\u@\h:\w\$\[$(tput sgr0)\] "
EOF
fi
chown "$SSH_USER:$SSH_USER" "$USER_HOME/.hushlogin" "$USER_HOME/.bashrc"

# --- 5. SSH hardening -------------------------------------------------------
# Remove existing drop-ins (e.g. 50-cloud-init.conf re-enables passwords).
rm -f /etc/ssh/sshd_config.d/*.conf

cat > /etc/ssh/sshd_config.d/00-hardening.conf << EOF
Port $SSH_PORT
PermitRootLogin no
AllowUsers $SSH_USER
MaxAuthTries 3
LoginGraceTime 30
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
AuthorizedKeysFile .ssh/authorized_keys
X11Forwarding no
EOF

# Validate config before restarting (aborts on error thanks to set -e).
sshd -t

# --- 6. UFW hardening -------------------------------------------------------
# Your current SSH session survives: UFW keeps established connections.
ufw --force reset

# Filter IPv6 too.
sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw

ufw default deny incoming
ufw default allow outgoing
ufw default deny routed

# SSH with rate limiting (blocks an IP after 6 connections in 30 seconds).
ufw limit "$SSH_PORT"/tcp comment 'SSH'

for p in $EXTRA_PORTS; do
  ufw allow "$p"
done

ufw logging low
ufw --force enable

# Kernel network hardening, applied through UFW's sysctl file (added once).
if ! grep -qE "added by (additional|server-harden).sh" /etc/ufw/sysctl.conf; then
  cat >> /etc/ufw/sysctl.conf << 'EOF'

# --- added by server-harden.sh ---
net/ipv4/tcp_syncookies=1
net/ipv4/conf/all/rp_filter=1
net/ipv4/conf/default/rp_filter=1
net/ipv4/conf/all/accept_redirects=0
net/ipv4/conf/default/accept_redirects=0
net/ipv4/conf/all/send_redirects=0
net/ipv4/conf/all/accept_source_route=0
net/ipv4/conf/all/log_martians=1
net/ipv4/icmp_echo_ignore_broadcasts=1
net/ipv6/conf/all/accept_redirects=0
net/ipv6/conf/default/accept_redirects=0
net/ipv6/conf/all/accept_source_route=0
EOF
fi
ufw reload

# --- 7. Restart SSH ---------------------------------------------------------
# Run sshd as a normal service instead of Ubuntu 22.10+ socket activation.
systemctl daemon-reload
systemctl disable --now ssh.socket 2> /dev/null || true
systemctl stop ssh 2> /dev/null || true
# ssh.service uses KillMode=process, so an old listener can survive the stop,
# keep the port busy and fail every login. Logged-in sessions are not touched.
pkill -f '^sshd: /usr/sbin/sshd.*\[listener\]' 2> /dev/null || true
sleep 1
systemctl enable ssh
systemctl start ssh

if ! ss -tln | grep -q ":$SSH_PORT\b"; then
  echo "WARNING: nothing is listening on port $SSH_PORT. Do NOT close this session." >&2
  echo "Check: systemctl status ssh; journalctl -u ssh -n 30" >&2
fi

echo
ufw status verbose
echo
echo "Done. Test from a NEW terminal before closing this one:"
echo "  ssh -p $SSH_PORT $SSH_USER@<server-ip>"
