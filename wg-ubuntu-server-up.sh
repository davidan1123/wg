#!/usr/bin/env bash
# usage:
#     wg-ubuntu-server-up.sh [--clients=<clients_count>] [--no-reboot] [--no-unbound]
#

set -e # exit when any command fails
set -x # enable print all commands

# constants:
working_dir="$HOME/wireguard"

# inputs:
clients=8
reboot_enabled=true
unbound_enabled=true

for arg in "$@"
do
  [[ "${arg}" == "--no-reboot" ]] && reboot_enabled=
  [[ "${arg}" == "--no-unbound" ]] && unbound_enabled=
  [[ "${arg}" == "--clients="* ]] && clients=${arg#*=}
done

# check a user is root
if [ "$(id -u)" != 0 ]; then
  echo Please, run the script as root: \"sudo ./wg-ubuntu-server-up.sh\"
  exit 1
fi
echo 'Port 4356' >> /etc/ssh/sshd_config
systemctl restart sshd
mkdir -p "${working_dir}"
mkdir -p "/etc/wireguard"

echo ---------------------------------------------------------update and upgrade
apt update -y && apt upgrade -y

echo ------------------------------------------------------install linux headers
apt install -y linux-headers-"$(uname -r)"

echo ----------------------------------------------------------install net-tools
apt install net-tools -y

echo ------------------------------------------install software-properties-common
apt install -y software-properties-common

echo ---------------------------------------------------------install wireguard
apt install -y wireguard
modprobe wireguard

echo ----------------------------------------------------------install qrencode
apt install -y qrencode

echo -------------------------------------------------- download wg-genconfig.sh
cd "${working_dir}" &&
wget https://raw.githubusercontent.com/davidan1123/wg/main/wg-genconf.sh
chmod +x ./wg-genconf.sh

echo ----------------------generate configurations for "${clients}" clients
if [[ ${unbound_enabled} ]]; then
   # use the wireguard server as a DNS resolver
  ./wg-genconf.sh "${clients}"
else
  # use the cloudflare as a DNS resolver
  ./wg-genconf.sh "${clients}" "1.1.1.1"
fi


echo -----------------------------------move server\'s config to /etc/wireguard/
mv -v ./wg0.conf \
      /etc/wireguard/
chown -v root:root /etc/wireguard/wg0.conf
chmod -v 600 /etc/wireguard/wg0.conf

echo ------------------------------------------------------------- run wireguard
wg-quick up wg0
systemctl enable wg-quick@wg0

echo ------------------------------------------------------enable IPv4 forwarding
sysctl net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-sysctl.conf

echo ---------------------------------------------------configure firewall rules


iptables -A INPUT -s 105.10.10.0/24 -p tcp -m tcp --dport 4356 -j ACCEPT
iptables -A INPUT -i eth0 -p udp -m udp --dport 52220 -j ACCEPT
iptables -A INPUT -i wg0 -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p udp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -p tcp -m tcp --dport 80 -m comment --comment "HTTP Port" -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 4356 -j LOG --log-prefix "SSH: "
iptables -A INPUT -p tcp -m tcp --dport 4356 -j DROP
iptables -A FORWARD -i eth0 -o wg0 -j ACCEPT
iptables -A FORWARD -i wg0 -o eth0 -j ACCEPT
iptables -A FORWARD -i wg0 -j ACCEPT
iptables -A FORWARD -o wg0 -j ACCEPT
iptables -A OUTPUT -p udp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -s 105.10.10.0/24 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 80 -m comment --comment "HTTP Port" -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 4356 -m comment --comment "SSH Port" -j ACCEPT
iptables -A OUTPUT -p icmp -j ACCEPT
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 105.10.10.0/24 -o eth0 -j MASQUERADE


# make firewall changes persistent
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

apt install -y iptables-persistent

systemctl enable netfilter-persistent
netfilter-persistent save

if [[ ${unbound_enabled} ]]; then
  echo ---------------------------------------------install and configure unbound
  apt install -y unbound unbound-host

  mkdir -p /var/lib/unbound
  curl -o /var/lib/unbound/root.hints https://www.internic.net/domain/named.cache
  echo 'curl -o /var/lib/unbound/root.hints https://www.internic.net/domain/named.cache' > /etc/cron.monthly/curl_root_hints.sh
  chmod +x /etc/cron.monthly/curl_root_hints.sh


  cat > /etc/unbound/unbound.conf << ENDOFFILE
server:
    num-threads: 4
    # disable logs
    verbosity: 0
    # list of root DNS servers
    root-hints: "/var/lib/unbound/root.hints"
    # use the root server's key for DNSSEC
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    # respond to DNS requests on all interfaces
    interface: 0.0.0.0
    max-udp-size: 3072
    # IPs authorised to access the DNS Server
    access-control: 0.0.0.0/0                 refuse
    access-control: 127.0.0.1                 allow
    access-control: 105.10.10.0/24             allow
    # not allowed to be returned for public Internet  names
    private-address: 105.10.10.0/24
    #hide DNS Server info
    hide-identity: yes
    hide-version: yes
    # limit DNS fraud and use DNSSEC
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-referral-path: yes
    # add an unwanted reply threshold to clean the cache and avoid, when possible, DNS poisoning
    unwanted-reply-threshold: 10000000
    # have the validator print validation failures to the log
    val-log-level: 1
    # minimum lifetime of cache entries in seconds
    cache-min-ttl: 1800
    # maximum lifetime of cached entries in seconds
    cache-max-ttl: 14400
    prefetch: yes
    prefetch-key: yes
    # don't use Capitalization randomization as it known to cause DNSSEC issues sometimes
    # see https://discourse.pi-hole.net/t/unbound-stubby-or-dnscrypt-proxy/9378 for further details
    use-caps-for-id: no
    # reduce EDNS reassembly buffer size.
    # suggested by the unbound man page to reduce fragmentation reassembly problems
    edns-buffer-size: 1472
    # ensure kernel buffer is large enough to not lose messages in traffic spikes
    so-rcvbuf: 1m
    # ensure privacy of local IP ranges
    private-address: 105.10.10.0/24
ENDOFFILE

  # give root ownership of the Unbound config
  chown -R unbound:unbound /var/lib/unbound

  # disable systemd-resolved
  systemctl stop systemd-resolved
  systemctl disable systemd-resolved

  # enable Unbound in place of systemd-resovled
  systemctl enable unbound
  systemctl start unbound
fi

# show wg
wg show

set +x # disable print all commands

echo && echo You can use this config: client2.conf
echo "--------------------------------------------------------↓"
qrencode -t ansiutf8 < ~/wireguard/client2.conf
echo "--------------------------------------------------------↑"
echo && echo You can use this config: client2.conf
echo "--------------------------------------------------------↓"
cat "${working_dir}/client1.conf"
echo "--------------------------------------------------------↑"

echo && echo "Or you could find all the generated configs here: ${working_dir}"
echo

# if WG_SCRIPT_DISABLE_REBOOT is not set, then
# reboot to make changes effective
if [[ ${reboot_enabled} ]]; then
  echo All done, reboot...
  reboot
fi

exit 0
