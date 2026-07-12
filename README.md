watch -n1 'iptables -L INPUT -v -n | egrep "Source Engine|autoban|DROP"'
watch ipset list autoban
