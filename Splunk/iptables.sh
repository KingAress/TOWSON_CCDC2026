# Empty all rules
iptables -t filter -F
iptables -t filter -X

# Block everything by default
iptables -t filter -P INPUT DROP
iptables -t filter -P FORWARD DROP
iptables -t filter -P OUTPUT DROP

# Authorize already established connections
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t filter -A INPUT -i lo -j ACCEPT
iptables -t filter -A OUTPUT -o lo -j ACCEPT

# ICMP (Ping)
iptables -t filter -A INPUT -p icmp -j ACCEPT
iptables -t filter -A OUTPUT -p icmp -j ACCEPT

# DNS (Needed for curl, and updates)
iptables -t filter -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 53 -j ACCEPT

# HTTP/HTTPS
iptables -t filter -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 443 -j ACCEPT

# NTP (server time)
iptables -t filter -A OUTPUT -p udp --dport 123 -j ACCEPT

# Splunk
iptables -t filter -A OUTPUT -p tcp --dport 8000 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 8089 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 9997 -j ACCEPT

# Splunk Web UI
iptables -t filter -A INPUT -p tcp --dport 8000 -j ACCEPT

# Splunk Forwarder
iptables -t filter -A INPUT -p tcp --dport 8089 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 9997 -j ACCEPT

# Splunk Syslog (PA)
iptables -t filter -A INPUT -p tcp --dport 514 -j ACCEPT

# Bad Flag Combinations
# Prevent an attacker from sending flags for reconnaissance. 
# These kinds of packets  typically are not done as an attack.
iptables -N BAD_FLAGS
iptables -A INPUT -p tcp -j BAD_FLAGS

# Fragmented Packets
iptables -A INPUT -f -j LOG --log-prefix "IT Fragmented "
iptables -A INPUT -f -j DROP

  # Set firewall rules
  chmod +x $IPTABLES_SCRIPT
  bash $IPTABLES_SCRIPT

  if [ ! -d /etc/iptables ]; then
    mkdir /etc/iptables
  fi

  # Save the rules
  iptables-save > /etc/iptables/rules.v4
