#!/bin/bash

echo "=== Instalando ipset e iptables-persistent ==="
apt update
apt install ipset iptables-persistent pure-ftpd -y

echo "=== Configurando Passive FTP ==="
echo "40110 40210" | tee /etc/pure-ftpd/conf/PassivePortRange
service pure-ftpd restart

echo "=== Limpando regras ==="
iptables -F
iptables -X

# Criar autoban
ipset create autoban hash:ip timeout 3600 -exist

# -------------------------
# ORDEM CORRETA COMEÇA AQUI
# -------------------------

# 1. Loopback
iptables -A INPUT -i lo -j ACCEPT

# 2. Conexões válidas
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 3. Invalid
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# 4. Banidos (ipset)
iptables -A INPUT -p udp -m set --match-set autoban src -j DROP

# -------------------------
# PROTEÇÕES CS 1.6
# -------------------------

# Challenge flood
iptables -A INPUT -p udp --dport 27015:27900 -m string --string "getchallenge" --algo bm \
-m hashlimit --hashlimit 10/sec --hashlimit-burst 20 \
--hashlimit-mode srcip --hashlimit-name challenge -j ACCEPT

iptables -A INPUT -p udp --dport 27015:27900 -m string --string "getchallenge" --algo bm -j DROP

# Pacotes pequenos (VSE flood)
iptables -A INPUT -p udp --dport 27015:27900 -m length --length 0:28 \
-m hashlimit --hashlimit 10/sec --hashlimit-burst 20 \
--hashlimit-mode srcip --hashlimit-name vse -j ACCEPT

iptables -A INPUT -p udp --dport 27015:27900 -m length --length 0:28 -j DROP

# Flood geral UDP
iptables -A INPUT -p udp --dport 27015:27900 \
-m hashlimit --hashlimit 40/sec --hashlimit-burst 80 \
--hashlimit-mode srcip --hashlimit-name cs16 -j ACCEPT

iptables -A INPUT -p udp --dport 27015:27900 -j DROP

# -------------------------
# LIBERAÇÕES TCP
# -------------------------

iptables -A INPUT -p tcp --dport 21 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
iptables -A INPUT -p tcp --dport 2121 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 3306 -j ACCEPT
iptables -A INPUT -p tcp --dport 12680 -j ACCEPT
iptables -A INPUT -p tcp --dport 8888 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 8989 -j ACCEPT

# Passive FTP
iptables -A INPUT -p tcp --dport 40110:40210 -j ACCEPT

# -------------------------
# NÃO precisa liberar UDP geral aqui
# (já está controlado acima)
# -------------------------

# Política padrão
iptables -P INPUT DROP

# Salvar regras
iptables-save > /etc/iptables/rules.v4

echo "=== Firewall + Anti-DDoS + FTP Passive ativo ==="
