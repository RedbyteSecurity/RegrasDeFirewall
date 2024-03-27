#!/bin/bash
# Rammon Pentest 

# Limpa todas as regras existentes
iptables -F
iptables -X

# Define a política padrão para DROP (descartar) para INPUT, FORWARD e OUTPUT
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Permite conexões já estabelecidas e relacionadas
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Bloqueia pings ICMP
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# Bloqueia scanners de portas com pacotes TCP SYN
iptables -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

# Bloqueia varreduras de portas com pacotes TCP NULL, FIN e XMAS
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP

# Bloqueia tentativas de identificação de versões de software pelo Nmap (-sV)
iptables -A INPUT -p tcp --tcp-flags ALL SYN,ACK -m connbytes --connbytes 3:3 --connbytes-dir reply --connbytes-mode packets -m recent --name nmap_vscan --set -j DROP

# Permite tráfego de loopback (comunicação interna)
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Permite conexões SSH na porta 22
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Permite conexões HTTP na porta 80
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# Exibe as regras configuradas
iptables -L -v

# Salva as regras para persistir após a reinicialização
iptables-save > /etc/iptables/rules.v4
