#!/bin/bash

# Forget old rules
iptables -F
iptables -X
iptables -Z

# Default policy: drop
iptables -P INPUT DROP
iptables -P OUTPUT ACCEPT
#iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# Allow loopback and reject traffic to localhost that does not originate from lo0
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT ! -i lo -s 127.0.0.0/8 -j REJECT
iptables -A OUTPUT -o lo -j ACCEPT

# Drop invalid packets
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP

# Allow ping
iptables -A INPUT -p icmp -m state --state NEW --icmp-type 8 -j ACCEPT

# Allow established, related packets already seen
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Input chain
iptables -A INPUT -p tcp --dport 65044 -m state --state NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT


# apt-get permissions
iptables -A OUTPUT -p tcp -m tcp --dport 53 -m comment --comment "DNS-TCP" -j ACCEPT
iptables -A OUTPUT -p udp -m udp --dport 53 -m comment --comment "DNS-UDP" -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 80 -m comment --comment "HTTP" -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 443 -m comment --comment "HTTPS" -j ACCEPT
