
iptables -F
iptables --table nat --flush
iptables --delete-chain

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

iptables -I INPUT -p tcp --dport 22 -j ACCEPT
iptables -I OUTPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

iptables -I INPUT -s 192.168.4.61 -j ACCEPT
iptables -I OUTPUT -s 192.168.4.61 -j ACCEPT
iptables -I FORWARD -s 192.168.4.61 -j ACCEPT

iptables -I INPUT -d 192.168.4.61 -j ACCEPT
iptables -I OUTPUT -d 192.168.4.61 -j ACCEPT
iptables -I FORWARD -d 192.168.4.61 -j ACCEPT

iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
