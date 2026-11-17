#!/usr/bin/env bash
# Generate a WireGuard server config (wg0.conf) plus one config per client.
#
# Usage:
#   ./wg-genconf.sh        asks each question; press Enter to keep the [default]
#   ./wg-genconf.sh -y     uses all defaults, asks nothing
#
# Any answer can also be preset with an environment variable, which skips
# that question: WG_CLIENTS, WG_ENDPOINT, WG_PORT, WG_SUBNET, WG_DNS, WG_OUT_DIR
set -euo pipefail

[[ "${1:-}" == "-y" || "${1:-}" == "--yes" ]] && ASSUME_YES=1
ASSUME_YES=${ASSUME_YES:-}

# ask VAR "question" default  -> sets VAR (unless already set)
ask() {
  local var=$1 question=$2 default=$3 answer
  [[ -n "${!var:-}" ]] && return
  if [[ -n "$ASSUME_YES" || ! -t 0 ]]; then
    printf -v "$var" '%s' "$default"
    return
  fi
  read -rp "$question [$default]: " answer
  printf -v "$var" '%s' "${answer:-$default}"
}

die() { echo "Error: $*" >&2; exit 1; }

command -v wg >/dev/null || die "'wg' not found. Install it first: sudo apt install wireguard"

detect_ip() {
  curl -4 -s --max-time 3 https://api.ipify.org 2>/dev/null ||
    hostname -I | awk '{print $1}'
}

# ---------------------------------------------------------------- questions
ask WG_CLIENTS  "How many client configs"            5
ask WG_ENDPOINT "Server public IP or hostname"       "$(detect_ip)"
ask WG_PORT     "WireGuard UDP port"                 52220
ask WG_SUBNET   "VPN subnet (first 3 numbers)"       10.10.10
ask WG_DNS      "DNS server for clients"             1.1.1.1
ask WG_OUT_DIR  "Save configs in"                    "$PWD"

[[ "$WG_CLIENTS" =~ ^[0-9]+$ ]] && (( WG_CLIENTS >= 1 && WG_CLIENTS <= 253 )) ||
  die "number of clients must be 1-253"
[[ "$WG_PORT" =~ ^[0-9]+$ ]] && (( WG_PORT >= 1 && WG_PORT <= 65535 )) ||
  die "port must be 1-65535"
[[ "$WG_SUBNET" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] ||
  die "subnet must look like 10.10.10"
[[ -n "$WG_ENDPOINT" ]] || die "server address is empty"

mkdir -p "$WG_OUT_DIR"
cd "$WG_OUT_DIR"
umask 077   # configs contain private keys

if [[ -e wg0.conf && -z "$ASSUME_YES" && -t 0 ]]; then
  read -rp "Configs already exist in $WG_OUT_DIR. Overwrite? [y/N]: " answer
  [[ "$answer" =~ ^[Yy] ]] || die "cancelled"
fi

# --------------------------------------------------------------- server conf
server_private_key=$(wg genkey)
server_public_key=$(wg pubkey <<<"$server_private_key")
wan_if=$(ip route show default | awk '{print $5; exit}')

cat > wg0.conf <<EOF
[Interface]
Address = ${WG_SUBNET}.1/24
ListenPort = ${WG_PORT}
PrivateKey = ${server_private_key}
PostUp   = iptables -I FORWARD 1 -i %i -j ACCEPT; iptables -I FORWARD 1 -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${wan_if} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${wan_if} -j MASQUERADE
EOF

# -------------------------------------------------------------- client confs
for i in $(seq 1 "$WG_CLIENTS"); do
  client_private_key=$(wg genkey)
  client_public_key=$(wg pubkey <<<"$client_private_key")
  client_ip=${WG_SUBNET}.$((i + 1))

  cat > "client$i.conf" <<EOF
[Interface]
PrivateKey = ${client_private_key}
Address = ${client_ip}/32
DNS = ${WG_DNS}

[Peer]
PublicKey = ${server_public_key}
AllowedIPs = 0.0.0.0/0
Endpoint = ${WG_ENDPOINT}:${WG_PORT}
PersistentKeepalive = 25
EOF

  cat >> wg0.conf <<EOF

[Peer]
# client$i
PublicKey = ${client_public_key}
AllowedIPs = ${client_ip}/32
EOF
done

echo
echo "Created in $WG_OUT_DIR:"
echo "  wg0.conf                 (server)"
echo "  client1.conf .. client${WG_CLIENTS}.conf  (clients, ${WG_SUBNET}.2 - ${WG_SUBNET}.$((WG_CLIENTS + 1)))"

# ------------------------------------------------- optional QR codes (phones)
[[ -n "${WG_SKIP_QR:-}" || -n "$ASSUME_YES" || ! -t 0 ]] && exit 0
command -v qrencode >/dev/null || exit 0
while true; do
  echo
  read -rp "Show QR code for client number (Enter to finish): " n
  [[ -z "$n" ]] && break
  if [[ -f "client$n.conf" ]]; then
    qrencode -t ansiutf8 < "client$n.conf"
  else
    echo "No client$n.conf"
  fi
done
