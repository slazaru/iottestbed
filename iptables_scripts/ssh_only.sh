
iptables -F
iptables --table nat --flush
iptables --delete-chain

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

iptables -I INPUT -p tcp --dport 22 -j ACCEPT
iptables -I OUTPUT -p tcp --sport 22 -j ACCEPT
iptables -I FORWARD -p tcp --dport 22 -j ACCEPT
iptables -I FORWARD -p tcp --sport 22 -j ACCEPT

iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
