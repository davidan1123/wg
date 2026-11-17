#!/usr/bin/env bash
# One-shot WireGuard VPN server setup for Ubuntu.
#
# Usage:
#   sudo ./wg-ubuntu-server-up.sh       asks a few questions, then installs
#   sudo ./wg-ubuntu-server-up.sh -y    uses all defaults, asks nothing
#
# It first offers to run server-harden.sh (sudo user, SSH keys only,
# custom SSH port, UFW). That part always asks questions, so -y skips it.
set -euo pipefail

ASSUME_YES=
[[ "${1:-}" == "-y" || "${1:-}" == "--yes" ]] && ASSUME_YES=1

working_dir="$HOME/wireguard"
repo_raw="https://raw.githubusercontent.com/davidan1123/wg/main"
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]:-.}")" && pwd)

# ------------------------------------------------------------------ helpers
die()  { echo "Error: $*" >&2; exit 1; }
step() { echo; echo "==> $*"; }

# sibling_script NAME -> path to NAME next to this script, downloaded if missing
sibling_script() {
  local path="$script_dir/$1"
  if [[ ! -f "$path" ]]; then
    path="$working_dir/$1"
    mkdir -p "$working_dir"
    curl -fsSL "$repo_raw/$1" -o "$path"
  fi
  echo "$path"
}

# ask VAR "question" default
ask() {
  local var=$1 question=$2 default=$3 answer=
  if [[ -z "$ASSUME_YES" ]]; then read -rp "$question [$default]: " answer; fi
  printf -v "$var" '%s' "${answer:-$default}"
}

# yes_no "question" y|n  -> exit status 0 for yes
yes_no() {
  local question=$1 default=$2 answer=
  local hint="[y/N]"; [[ $default == y ]] && hint="[Y/n]"
  if [[ -z "$ASSUME_YES" ]]; then read -rp "$question $hint: " answer; fi
  [[ "${answer:-$default}" =~ ^[Yy] ]]
}

# ------------------------------------------------------------------- checks
[[ $(id -u) == 0 ]] || die "run as root: sudo $0"
command -v apt-get >/dev/null || die "this script is for Ubuntu/Debian"
[[ -z "$ASSUME_YES" && ! -t 0 ]] && die "no terminal to ask questions; run with -y to use defaults"

if [[ -e /etc/wireguard/wg0.conf ]]; then
  yes_no "WireGuard is already set up (/etc/wireguard/wg0.conf). Replace it and all client keys?" n ||
    die "cancelled, nothing changed"
fi

hardened=
if yes_no "Harden the server first (sudo user, SSH keys only, custom SSH port, UFW)?" n; then
  step "Server hardening (the WireGuard port is opened later, no need to list it)"
  bash "$(sibling_script server-harden.sh)"
  hardened=1
  echo
fi

detected_ip=$(curl -4 -s --max-time 3 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
current_ssh_port=$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2; exit}')
current_ssh_port=${current_ssh_port:-22}

# ---------------------------------------------------------------- questions
echo "WireGuard server setup. Press Enter to accept the [default]."
echo
ask clients  "How many client configs"         5
ask endpoint "Server public IP or hostname"    "$detected_ip"
ask wg_port  "WireGuard UDP port"              52220
ask subnet   "VPN subnet (first 3 numbers)"    10.10.10
if yes_no "Run a private DNS resolver (Unbound) on this server?" y; then
  unbound=1; dns="${subnet}.1"
else
  unbound=;  ask dns "DNS server for clients" 1.1.1.1
fi
if [[ $hardened ]]; then
  ssh_port=$current_ssh_port   # already chosen during hardening
else
  ask ssh_port "SSH port (change only if you want a new one)" "$current_ssh_port"
fi
yes_no "Reboot when finished?" n && reboot_after=1 || reboot_after=

valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }
[[ "$clients" =~ ^[0-9]+$ ]] && (( clients >= 1 && clients <= 253 )) || die "clients must be 1-253"
valid_port "$wg_port"  || die "WireGuard port must be 1-65535"
valid_port "$ssh_port" || die "SSH port must be 1-65535"
[[ "$subnet" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || die "subnet must look like 10.10.10"
[[ -n "$endpoint" ]] || die "server address is empty"

cat <<EOF

  Clients        : $clients
  Endpoint       : $endpoint:$wg_port (udp)
  VPN subnet     : $subnet.0/24 (server $subnet.1)
  Client DNS     : $dns $([[ $unbound ]] && echo "(Unbound on this server)")
  SSH port       : $ssh_port $([[ $ssh_port != "$current_ssh_port" ]] && echo "(changing from $current_ssh_port)")
  Reboot at end  : $([[ $reboot_after ]] && echo yes || echo no)
  Configs saved  : $working_dir

EOF
yes_no "Continue?" y || die "cancelled, nothing changed"

# ------------------------------------------------------------------ install
export DEBIAN_FRONTEND=noninteractive

step "Installing packages"
apt-get update -y
apt-get install -y wireguard qrencode curl ${unbound:+unbound}

step "Generating configs"
genconf=$(sibling_script wg-genconf.sh)
ASSUME_YES=1 WG_SKIP_QR=1 \
WG_CLIENTS="$clients" WG_ENDPOINT="$endpoint" WG_PORT="$wg_port" \
WG_SUBNET="$subnet" WG_DNS="$dns" WG_OUT_DIR="$working_dir" \
  bash "$genconf"

install -d -m 700 /etc/wireguard
install -m 600 -o root -g root "$working_dir/wg0.conf" /etc/wireguard/wg0.conf
rm -f "$working_dir/wg0.conf"

step "Enabling IP forwarding"
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-wireguard.conf
sysctl -p /etc/sysctl.d/99-wireguard.conf

step "Starting WireGuard"
systemctl enable wg-quick@wg0
systemctl restart wg-quick@wg0

if [[ $unbound ]]; then
  step "Configuring Unbound DNS"
  cat > /etc/unbound/unbound.conf.d/wireguard.conf <<EOF
server:
    interface: 127.0.0.1
    interface: ${subnet}.1
    ip-freebind: yes
    access-control: 127.0.0.0/8 allow
    access-control: ${subnet}.0/24 allow
    private-address: ${subnet}.0/24
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: no
    prefetch: yes
    verbosity: 0
EOF
  unbound-checkconf
  systemctl enable unbound
  systemctl restart unbound
fi

if [[ "$ssh_port" != "$current_ssh_port" ]]; then
  step "Changing SSH port to $ssh_port"
  echo "Port $ssh_port" > /etc/ssh/sshd_config.d/99-port.conf
  if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then ufw allow "$ssh_port/tcp"; fi
  sshd -t
  systemctl daemon-reload
  # Ubuntu 22.10+ may use socket activation (the port comes from sshd_config
  # on daemon-reload). Stop both, then remove any leftover listener: with
  # KillMode=process it can survive the stop, hold the port and fail every login.
  systemctl stop ssh.socket ssh 2>/dev/null || true
  pkill -f '^sshd: /usr/sbin/sshd.*\[listener\]' 2>/dev/null || true
  sleep 1
  if systemctl is-enabled --quiet ssh.socket 2>/dev/null; then systemctl start ssh.socket; else systemctl start ssh; fi
  ss -tln | grep -q ":$ssh_port\b" || echo "WARNING: nothing listens on port $ssh_port yet. Do NOT close this session."
  echo "Keep this session open and test: ssh -p $ssh_port <user>@$endpoint"
fi

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  step "Opening firewall (ufw)"
  ufw allow "$wg_port/udp"
  [[ $unbound ]] && ufw allow in on wg0 to any port 53
  ufw route allow in on wg0
fi

# --------------------------------------------------------------------- done
step "Done"
wg show
echo
echo "Client configs are in $working_dir:"
ls -1 "$working_dir"/client*.conf | sed 's/^/  /'
echo "Copy one to each device, or scan its QR code in the WireGuard phone app."

if [[ -z "$ASSUME_YES" ]]; then
  while true; do
    echo
    read -rp "Show QR code for client number (Enter to finish): " n
    [[ -z "$n" ]] && break
    if [[ -f "$working_dir/client$n.conf" ]]; then
      qrencode -t ansiutf8 < "$working_dir/client$n.conf"
    else
      echo "No client$n.conf"
    fi
  done
fi

if [[ $reboot_after ]]; then
  echo "Rebooting..."
  reboot
fi
