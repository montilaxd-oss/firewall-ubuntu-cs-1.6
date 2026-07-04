#!/bin/bash

echo "=== Instalando dependências ==="
apt update
DEBIAN_FRONTEND=noninteractive apt install -y \
iptables ipset tcpdump iptables-persistent netfilter-persistent

echo "=== Configurando Passive FTP ==="
echo "40110 40210" | tee /etc/pure-ftpd/conf/PassivePortRange
service pure-ftpd restart

echo "=== Limpando regras ==="
iptables -F
iptables -X
iptables -Z

# =========================
# IPSET
# =========================

ipset destroy autoban 2>/dev/null
ipset destroy whitelist 2>/dev/null

ipset create autoban hash:ip timeout 6000
ipset create whitelist hash:ip

# SUA WHITELIST
ipset add whitelist 177.54.151.114
ipset add whitelist 177.54.151.234

# =========================
# BASE
# =========================

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Loopback
iptables -A INPUT -i lo -j ACCEPT

# Established
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Invalid
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Whitelist
iptables -I INPUT 1 -m set --match-set whitelist src -j ACCEPT

# Autoban
iptables -I INPUT 2 -m set --match-set autoban src -j DROP

# =========================
# ANTI-SPOOF
# =========================

iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -s 10.0.0.0/8 -j DROP
iptables -A INPUT -s 100.64.0.0/10 -j DROP
iptables -A INPUT -s 127.0.0.0/8 -j DROP
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -j DROP
iptables -A INPUT -s 192.168.0.0/16 -j DROP
iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/4 -j DROP

# Fragmentados
iptables -A INPUT -f -j DROP

# =========================
# ICMP
# =========================

iptables -A INPUT -p icmp --icmp-type echo-request \
-m limit --limit 5/sec -j ACCEPT

# =========================
# TCP LIBERADO
# =========================

for port in 22 2222 21 2121 80 443 8080 8888 3306 12679 38151; do
    iptables -A INPUT -p tcp --dport $port -j ACCEPT
done

iptables -A INPUT -p tcp --dport 40110:40210 -j ACCEPT

# =========================
# CS 1.6 HARDCORE
# =========================

# Pacotes pequenos
iptables -A INPUT -p udp --dport 27010:27999 \
-m length --length 0:32 \
-j SET --add-set autoban src

# Pacotes grandes suspeitos
iptables -A INPUT -p udp --dport 27010:27999 \
-m length --length 600:65535 \
-j SET --add-set autoban src

# getchallenge flood
iptables -A INPUT -p udp --dport 27010:27999 \
-m string --string "getchallenge" --algo bm \
-m hashlimit --hashlimit 8/sec --hashlimit-burst 16 \
--hashlimit-mode srcip --hashlimit-name getchallenge_limit \
-j ACCEPT

iptables -A INPUT -p udp --dport 27010:27999 \
-m string --string "getchallenge" --algo bm \
-j SET --add-set autoban src

# A2S_INFO normal
iptables -A INPUT -p udp --dport 27010:27999 \
-m length --length 33:80 \
-m hashlimit --hashlimit 15/sec --hashlimit-burst 30 \
--hashlimit-mode srcip --hashlimit-name a2s_limit \
-j ACCEPT

# Source Engine Query
iptables -I INPUT 1 -p udp --dport 27010:27999 \
-m string --string "Source Engine Query" --algo bm \
-m hashlimit --hashlimit 15/sec --hashlimit-burst 40 \
--hashlimit-mode srcip --hashlimit-name a2s_query \
-j ACCEPT

iptables -I INPUT 2 -p udp --dport 27010:27999 \
-m string --string "Source Engine Query" --algo bm \
-j DROP

# Flood UDP geral
iptables -A INPUT -p udp --dport 27010:27999 \
-m hashlimit --hashlimit 20/sec --hashlimit-burst 40 \
--hashlimit-mode srcip --hashlimit-name cs_udp_limit \
-j ACCEPT

# Resto = autoban
iptables -A INPUT -p udp --dport 27010:27999 \
-j SET --add-set autoban src

iptables -A INPUT -p udp --dport 27010:27999 -j DROP

# =========================
# PERSISTÊNCIA
# =========================

iptables-save > /etc/iptables/rules.v4

mkdir -p /etc/ipset
ipset save > /etc/ipset/rules

cat > /etc/network/if-pre-up.d/ipset << 'EOF'
#!/bin/sh
ipset restore < /etc/ipset/rules
exit 0
EOF

chmod +x /etc/network/if-pre-up.d/ipset

systemctl enable netfilter-persistent
systemctl restart netfilter-persistent

echo "========================================"
echo "CS 1.6 HARDCORE PROTECTION UBUNTU ATIVA"
echo "Autoban: 6000"
echo "Passive FTP"
echo "Whitelist ativa"
echo "Anti-spoof ativo"
echo "Fragment drop ativo"
echo "========================================"
