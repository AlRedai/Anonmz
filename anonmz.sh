#!/bin/bash

# Tor-Autistici Vpn Anonymizer
# requires: xargs ipcalc curl timeout egrep
# Tested on debian and ubuntu

DNS="53"
TCP="9040"
BND="9050"
CTR="9051"
TNB="9052"
TNC="9053"
PWD_CTR="test"
VPN_IF="tun0"
VPN_IF2="tun1"
HST="127.0.0.1"
TOR=`which tor`
TORRC="/etc/tor/torrc"
CMD=`basename $0`
ID=`id -u debian-tor`
OPENVPN_LOG="vpn.log"
OPENVPN_DIR="/home/inside/Scrivania/vpn"
OPENVPN_CONF=`ls $OPENVPN_DIR | head -n 7 | tail -n 1`
#OPENVPN_CONF=`ls $OPENVPN_DIR | grep .conf`
TOUT1="10s"
TOUT2="30s"
UIDTOR="0"
UIDVPN="1000"

if [ $EUID -eq 0 ]; then
	#ETH_IF=`ip route show | grep default | awk '{print $5}' | sort -u`
	ETH_IF=`ip neigh show | awk '{print $3}' | sort -u`
    non_tor=`ip addr show | grep -o "inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" | grep -o "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*"`
    if [ `cat /proc/net/dev | grep ${ETH_IF} | wc -l` -eq 1 ]; then
		inet_eth=`ifconfig ${ETH_IF} | grep -wo "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" | head -n 1`
		network_eth=`echo ${inet_eth} | xargs ipcalc | grep "Network:" | awk '{print $2}'`
		gw_eth=`echo ${inet_eth} | xargs ipcalc | grep "HostMin:" | awk '{print $2}'`
	fi
	if [ `cat /proc/net/dev | grep ${VPN_IF} | wc -l` -eq 1 ]; then
		inet_tun=`ifconfig ${VPN_IF} | grep -wo "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" | head -n 1`
		pptp_tun=`ifconfig ${VPN_IF} | grep -wo "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" | head -n 2 | tail -n 1`
		network_tun=`echo ${inet_tun} | xargs ipcalc | grep "Network:" | awk '{print $2}'`	
	fi
	if [ `cat /proc/net/dev | grep ${VPN_IF2} | wc -l` -eq 1 ]; then
		inet_tun1=`ifconfig ${VPN_IF2} | grep -wo "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" | head -n 1`
		pptp_tun1=`ifconfig ${VPN_IF2} | grep -wo "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" | head -n 2 | tail -n 1`
		network_tun1=`echo ${inet_tun1} | xargs ipcalc | grep "Network:" | awk '{print $2}'`	
	fi
fi

function help() {
cat << EOF
[*] Tor Autistici Vpn Hacking Anonymizer.
    Digit: $CMD [option]

 -i | --install        [ Config torrc and create bind.so ]
 -c | --conf           [ Setup openvpn.conf connection ]
       -c del          [ Delete old ssl certificate ]  
 -n | --newnym         [ Change Tor-Exit-Node ]
       -n new   <port> [ Change identity tor ]
       -n <sec> <port> [ Cycle  identity tor default:600sec/min:10sec ]
       -n run          [ Run  node tor on port 9052 ctrl 9053 ]
       -n stop         [ Stop node tor on port 9052 ctrl 9053 ]
 -o | --openv	       [ Openvpn Lunch (default: udp)]
       -o daemon       [ Openvpn Udp daemon ]       
       -o daemon tcp   [ Openvpn Tcp daemon ]
       -o log tcp      [ Openvpn Tcp log ]    
       -o log udp      [ Openvpn Udp log ]
       -o tor daemon   [ Openvpn with torify tun0 daemon ] 
       -o tor log      [ Openvpn with torify tun0 log ]
       -o tor split    [ Openvpn with torify tun1 log ] 
 -p | --proxy	       [ Tor Trasparent Proxy ]
 -v | --vpntor	       [ Vpn over Tor ]
 -t | --torvpn         [ Tor Over Vpn ]
 -l | --lunch          [ Lunch command through tor over vpn ]
       -l <cmd>        [ Example: $CMD -l firefox ]  
 -f | --flush	       [ Flush iptables rules]
       -f all          [ Flush iptables and routing, stop openvpn, tor restart ]
 -s | --split          [ Tor over tun1 and dynamic ip over tun0 daemon]
 -k | --kill	       [ Flush rules and kill openvpn ]
 -u | --undertor <cmd> [ Proxychains cmd on port 9052 ]
 -h | --help	       [ Print menu options ]

EOF
}

function rootctrl() {
	if [ $EUID -ne 0 ]; then
		help
		echo " **** [You should be ROOT] **** "
		exit 0
	fi
}

function vpncontrol() {
	inet_tun=`ifconfig ${VPN_IF} | grep -wo "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" | head -n 1`
	dynamic=`curl -s http://ipecho.net/plain 2>&1`
	#dynamic=`stdbuf -oL curl -s http://ipecho.net/plain`
	sleep 1
	hostname=`curl -s http://ipecho.net/plain 2>&1 | xargs host | awk '{print $5}'`
	echo "Vpn on $VPN_IF addr $inet_tun [$dynamic] $hostname"
}

function install() {
	rootctrl
	HASH=`${TOR} --hash-password "${PWD_CTR}" | tail -n 1`
	echo "[*] Setup Torrc for TransPort and DnsPort."
	result=$(egrep '^[[:space:]]*ControlPort[[:space:]]+[[:digit:]]+[[:space:]]*#*.*$' $TORRC | grep -o "[0-9]*")
	if [ -z "$result" ]; then
		cat << EOF >> $TORRC
ControlPort $CTR
HashedControlPassword ${HASH} 
EOF
	fi
	result=$(egrep '^[[:space:]]*VirtualAddrNetwork[[:space:]]+[[:digit:]]+[[:space:]]*#*.*$' $TORRC | grep -o "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*")
	if [ -z "$result" ]; then
		echo "VirtualAddrNetwork 10.192.0.0/10" >> $TORRC
	fi
	result=$(egrep '^[[:space:]]*AutomapHostsOnResolve[[:space:]]+[[:digit:]]+[[:space:]]*#*.*$' $TORRC | grep -o "[0-9]*")
	if [ -z "$result" ]; then
		echo "AutomapHostsOnResolve 1" >> $TORRC
	fi
	result=$(egrep '^[[:space:]]*TransPort[[:space:]]+[[:digit:]]+[[:space:]]*#*.*$' $TORRC | grep -o "[0-9]*")
	if [ -z "$result" ]; then
		echo "TransPort $TCP" >> $TORRC
	fi
	result=$(egrep '^[[:space:]]*DNSPort[[:space:]]+[[:digit:]]+[[:space:]]*#*.*$' $TORRC | grep -o "[0-9]*")
	if [ -n "$result" ]; then
		echo "DNSPort $DNS" >> $TORRC
	fi	
cat << EOF >> /usr/lib/bind.c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <dlfcn.h>
#include <errno.h>
int (*real_bind)(int, const struct sockaddr *, socklen_t);
int (*real_connect)(int, const struct sockaddr *, socklen_t);
char *bind_addr_env;
unsigned long int bind_addr_saddr;
unsigned long int inaddr_any_saddr;
struct sockaddr_in local_sockaddr_in[] = { 0 };
void _init (void){
const char *err;
real_bind = dlsym (RTLD_NEXT, "bind");
if((err = dlerror ()) != NULL) {
fprintf (stderr, "dlsym (bind): %s\n", err);}
real_connect = dlsym (RTLD_NEXT, "connect");
if((err = dlerror ()) != NULL) {
fprintf (stderr, "dlsym (connect): %s\n", err);}
inaddr_any_saddr = htonl(INADDR_ANY);
if(bind_addr_env = getenv("BIND_ADDR")) {
bind_addr_saddr = inet_addr (bind_addr_env);
local_sockaddr_in->sin_family = AF_INET;
local_sockaddr_in->sin_addr.s_addr = bind_addr_saddr;
local_sockaddr_in->sin_port = htons (0);}}
int bind(int fd, const struct sockaddr *sk, socklen_t sl){
static struct sockaddr_in *lsk_in;
lsk_in = (struct sockaddr_in *)sk;
printf("bind: %d %s:%d\n", fd, inet_ntoa(lsk_in->sin_addr.s_addr),ntohs(lsk_in->sin_port));
if((lsk_in->sin_family == AF_INET) && (lsk_in->sin_addr.s_addr == inaddr_any_saddr) && (bind_addr_env)) {
lsk_in->sin_addr.s_addr = bind_addr_saddr;}
return real_bind (fd, sk, sl);}
int connect(int fd, const struct sockaddr *sk, socklen_t sl){
static struct sockaddr_in *rsk_in;	
rsk_in = (struct sockaddr_in *)sk;
printf("connect: %d %s:%d\n", fd, inet_ntoa(rsk_in->sin_addr.s_addr), ntohs(rsk_in->sin_port));
if((rsk_in->sin_family == AF_INET) && (bind_addr_env)) {
real_bind(fd, (struct sockaddr *)local_sockaddr_in, sizeof (struct sockaddr));}
return real_connect(fd, sk, sl);}
EOF
	gcc -nostartfiles -fpic -shared /usr/lib/bind.c -o /usr/lib/bind.so -ldl -D_GNU_SOURCE
	rm -f /usr/lib/bind.c
	echo "200	torvpn" >> /etc/iproute2/rt_tables
	/etc/init.d/tor restart | grep Opening | awk -F'] ' '{print $2}'
}

function torrc_config() {
	HASH=`${TOR} --hash-password "${PWD_CTR}" | tail -n 1`
cat << EOF
SocksBindAddress $HST
SocksPort $TNB
SocksPolicy accept *
Log notice syslog
RunAsDaemon 0
AllowUnverifiedNodes middle,rendezvous
CircuitBuildTimeout 30
NumEntryGuards 3
KeepalivePeriod 60
NewCircuitPeriod 15
ControlListenAddress $HST:$TNC
ControlPort $TNC
HashedControlPassword ${HASH} 
DataDirectory /var/lib/tor-1
PidFile /var/run/tor/tor-1.pid
EOF
}

function nodeinstall() {
	rootctrl
	if [ -f /etc/tor/torrc-1 ]; then
		echo " Template ${TORDIR}/torrc already installed."
	else
		torrc_config >> /etc/tor/torrc-1
		/usr/bin/install -o debian-tor -g debian-tor -m 700 -d /var/lib/tor-1
		echo "[*] Node install on $HST:$TNB:$TNC" 
	fi
}

function node_run() {
	rootctrl
	echo "[*] Run tor node on $HST:$TNB::$TNC"
	addr=`ip rule show | grep torvpn | head -n1 | awk '{print $5}'`
	BIND_ADDR=$addr LD_PRELOAD=/usr/lib/bind.so ${TOR} -f /etc/tor/torrc-1
}

function node_stop() {
	echo "[*] Stop tor node on $HST:$TNB"
	printf "AUTHENTICATE \"%s\"\r\nSIGNAL SHUTDOWN\n" "${PWD_CTR}" | nc $HST $TNC
}

function configure() {
	if [ "$1" == "del" ]; then
		echo "[*] Delete openvpn.conf old connection."
		rm -rf $OPENVPN_DIR/*
	else
		echo "[*] Setup openvpn.conf protocol connection."
		cd $OPENVPN_DIR && cp $OPENVPN_CONF openvpn.tcp.conf && cp openvpn.tcp.conf openvpn.udp.conf
		sed -i '1 s/^/verb 5/' openvpn.tcp.conf
		sed -i '1 s/^/verb 5/' openvpn.udp.conf
		sed -i '9 s/^/;/' openvpn.tcp.conf
		sed -i '10 s/^/;/' openvpn.tcp.conf
		sed -i '11 s/^/;/' openvpn.tcp.conf
		sed -i '13 s/^/;/' openvpn.udp.conf
		sed -i '14 s/^/;/' openvpn.udp.conf
		sed -i '15 s/^/;/' openvpn.udp.conf
	fi
}

function newnym() {
	if [ "$1" == "new" ]; then
		echo "[*] Change exit node on $HST:$2"
		printf "AUTHENTICATE \"%s\"\nSIGNAL NEWNYM\nquit\n" "${PWD_CTR}" | nc $HST $2
	fi
	if [ "$1" == "run" ]; then
		nodeinstall
		node_run
	fi
	if [ "$1" == "stop" ]; then
		node_stop
		exit 0
	fi	
	if [[ "$1" == ?(-)+([0-9.]) ]]; then
		printf "AUTHENTICATE \"%s\"\nsetconf MaxCircuitDirtiness=%s\ngetconf MaxCircuitDirtiness\nquit\n" $PWD_CTR $1 | nc $HST $2
	fi
}

function cycler() {
	for i in {1..10}
	do
		printf "AUTHENTICATE \"%s\"\nSIGNAL NEWNYM\nquit\n" "${PWD_CTR}" | nc $HST $2 > /dev/null 2>&1
		sleep .3
	done
}

function bootstrap() {
	while true; do
		#timeout -k 10s 10s tail -f ${OPENVPN_DIR}/vpnlog | grep "Initialization Sequence Completed" > /dev/null 2>&1
		timeout $1 tail -f ${OPENVPN_DIR}/vpnlog | grep "Initialization Sequence Completed" > /dev/null 2>&1
		break
	done
}

function openv() {
	rootctrl
	#killall -9 openvpn > /dev/null 2>&1
	if [ "$1" == "daemon" -o "$*" == ""  ]; then
		echo "[*] Start openvpn daemon udp."
		openvpn --daemon --cd ${OPENVPN_DIR} --log vpnlog --config openvpn.udp.conf
		bootstrap 10s
		vpncontrol
		/etc/init.d/tor restart | grep Opening | awk -F'] ' '{print $2}'
		cycler		
	fi	
	if [ "$1" == "daemon" -a "$2" == "tcp" ]; then
		echo "[*] Start openvpn daemon tcp."
		openvpn --daemon --cd ${OPENVPN_DIR} --log vpnlog --config openvpn.tcp.conf
		bootstrap 10s
		vpncontrol
		/etc/init.d/tor restart | grep Opening | awk -F'] ' '{print $2}'
		cycler		
	fi
	if 	[ "$1" == "log" -a "$2" == "tcp" ]; then
		echo "[*] Start openvpn log tcp."
		openvpn --cd ${OPENVPN_DIR} --config openvpn.tcp.conf
	fi
	if [ "$1" == "log" -a "$2" == "udp" ]; then
		echo "[*] Start openvpn log udp."
		openvpn --cd ${OPENVPN_DIR} --config openvpn.udp.conf
	fi	
	if [ "$1" == "tor" -a "$2" == "daemon" ]; then
		echo "[*] Start torify openvpn daemon."
		torify openvpn --daemon --cd ${OPENVPN_DIR} --log vpnlog --config openvpn.tcp.conf
		bootstrap 30s
	fi
	if [ "$1" == "tor" -a "$2" == "log" ]; then
		echo "[*] Start torify openvpn log."
		torify openvpn --cd ${OPENVPN_DIR} --config openvpn.tcp.conf
	fi
	if [ "$1" == "tor" -a "$2" == "split" ]; then
		echo "[*] Start torify openvpn log dev tun1."
		sleep 1
		torify openvpn --cd ${OPENVPN_DIR} --config openvpn.tcp.conf --dev $VPN_IF2
	fi
}

function default_routing_table() { 
	rootctrl  
	ip route flush table main
	ip route flush table torvpn
	ip route flush table 21
	ip rule flush
	ip rule add lookup default priority 32767
	ip rule add lookup main priority 32766
	ip rule add priority 2000 table 21
	ip route add $network_eth dev $ETH_IF src $inet_eth
	ip route add default via $gw_eth
	ip route add $network_eth dev $ETH_IF table 21
	ip route add default via $gw_eth dev $ETH_IF table 21
}

function flush() {
	rootctrl
	echo "[*] Reset iptables rules..."
	iptables -F
	iptables -t mangle -F
	iptables -t nat -F
	iptables -t filter -F
	iptables -X
	iptables -t mangle -X
	iptables -t nat -X
	iptables -P INPUT ACCEPT
	iptables -P FORWARD ACCEPT
	iptables -P OUTPUT ACCEPT
	cp /etc/resolv.conf.orig /etc/resolv.conf
	for table in filter; do
		ip6tables -t "$table" -F
	done
	if [ "$1" == "all" ]; then 
		default_routing_table
		killall -9 openvpn > /dev/null 2>&1
		/etc/init.d/tor restart | grep Opening | awk -F'] ' '{print $2}'
	fi
}

function killOpFw() {
	rootctrl	
	flush 
	if [ -z "$(pgrep openvpn)" ]; then
		echo "[*] Openvpn not running."
	else
		echo "[*] Openvpn kill -TERM."
		killall -9 openvpn > /dev/null 2>&1
		route del 91.121.204.114 gw $gw_eth > /dev/null
	fi
}

function dnsleak() {
	cp /etc/resolv.conf /etc/resolv.conf.orig
	echo "nameserver 127.0.0.1" > /etc/resolv.conf
}

function ipv6_drop() {
	rootctrl
    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT DROP
    ip6tables -t filter -I INPUT 1 -j DROP
    ip6tables -t filter -I INPUT 1 -i lo -j ACCEPT
    ip6tables -t filter -I FORWARD 1 -j DROP
    ip6tables -t filter -I OUTPUT 1 -j DROP
    ip6tables -t filter -I OUTPUT 1 -o lo -j ACCEPT
}

function trasparent_proxy() {
	rootctrl
	echo "[*] Tor Trasparent Proxy start...."			
	dnsleak	
	iptables -F
	iptables -t nat -F 	
	iptables -t nat -A OUTPUT -p tcp -d 10.192.0.0/10 -j REDIRECT --to-ports $TCP
	iptables -t nat -A OUTPUT -m owner --uid-owner $ID -j RETURN
	iptables -t nat -A OUTPUT -p udp --dport $DNS -j REDIRECT --to-ports $DNS
	for NET in $non_tor; do
		iptables -t nat -A OUTPUT -d $NET -j RETURN
	done
	iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports $TCP
	iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT	
	for NET in $non_tor; do
		iptables -A OUTPUT -d $NET -j ACCEPT 
	done
	iptables -A OUTPUT -m owner --uid-owner $ID -j ACCEPT
	iptables -A OUTPUT -p icmp -j REJECT --reject-with icmp-net-prohibited
	ipv6_drop
	sleep 1	
	exitnode=`curl -s http://ipecho.net/plain 2>&1`
	sleep 1
	hostname=`curl -s http://ipecho.net/plain 2>&1 | xargs host | awk '{print $5}'`
	echo "Exit-node: $exitnode $hostname"

}

function vpn_over_tor() {
	rootctrl
	echo "[*] Vpn Over Tor start...."
	openvpn --daemon --cd ${OPENVPN_DIR} --log vpnlog --config openvpn.tcp.conf # daemon openvpn
	bootstrap 10s
	trasparent_proxy
}

function tor_over_vpn() {
	rootctrl
	echo "[*] Tor over Vpn start...."	
	dnsleak
	if [ "$1" == "daemon" ]; then 
		torify openvpn --daemon --cd ${OPENVPN_DIR} --log vpnlog --config openvpn.tcp.conf
		bootstrap 30s
	fi
    default_routing_table
	ip route add $network_tun dev $VPN_IF src $inet_tun table torvpn
	ip route add default via $inet_tun dev $VPN_IF table torvpn
	ip rule add from $inet_tun/32 table torvpn
	ip rule add to $inet_tun/32 table torvpn	
	iptables -t nat -A OUTPUT -o $VPN_IF -p udp --dport $DNS -j REDIRECT --to-ports $DNS
    iptables -t nat -A POSTROUTING -o $VPN_IF -j MASQUERADE	
	iptables -A OUTPUT -p icmp -j REJECT --reject-with icmp-net-prohibited
	ipv6_drop
	printf "AUTHENTICATE \"%s\"\r\ngetinfo stream-status\n" "${PWD_CTR}" | nc $HST $CTR  | head -n2 | tail -n1
}

function split_connection() {			
	rootctrl
	echo "[*] Split Connection: Ip-<>-Vpn[tun0] && Tor-<>-Vpn[tun1]."		
	dnsleak
	if [ "$1" == "daemon" ]; then
		openvpn --daemon --cd ${OPENVPN_DIR} --log vpnlog --config openvpn.tcp.conf
		bootstrap 10s
		sleep 1
		torify openvpn --daemon --cd ${OPENVPN_DIR} --log vpnlog --config openvpn.tcp.conf
		bootstrap 30s
	fi
	ip route flush table main
	ip route flush table torvpn
	ip route flush table 11
	ip route flush table 12
	ip route flush table 21
	ip rule flush
	ip rule add lookup default priority 32767
	ip rule add lookup main priority 32766
	ip rule add fwmark 11 priority 1000 table 11
	ip rule add fwmark 12 priority 1500 table torvpn
	ip rule add priority 2000 table 21
	ip route add $network_eth dev $ETH_IF src $inet_eth
	ip route add default via $gw_eth
	ip route add $network_eth dev $ETH_IF table 21
	ip route add default via $gw_eth dev $ETH_IF table 21	
	ip route add $pptp_tun/32 dev $VPN_IF table 11   
	ip route add $network_tun via $inet_tun dev $VPN_IF table 11   	
	ip route add 0.0.0.0/1 via $inet_tun dev $VPN_IF table 11   	
	ip route add $network_tun1 dev $VPN_IF2 src $inet_tun1 table torvpn
	ip route add default via $inet_tun1 dev $VPN_IF2 table torvpn
	ip rule add from $inet_tun1/32 table torvpn
	ip rule add to $inet_tun1/32 table torvpn		
	ip route flush cache
	iptables -t mangle -A OUTPUT -m owner --uid-owner $UIDVPN -j MARK --set-mark 11
	iptables -t nat -A POSTROUTING -m owner --uid-owner $UIDVPN -o $VPN_IF -j MASQUERADE	
	iptables -t mangle -A OUTPUT -p tcp -m owner --uid-owner $UIDTOR -j MARK --set-mark 12
	iptables -t nat -A OUTPUT -m owner --uid-owner $UIDTOR -o $VPN_IF2 -p udp --dport $DNS -j REDIRECT --to-ports $DNS
    iptables -t nat -A POSTROUTING -m owner --uid-owner $UIDTOR -o $VPN_IF2 -j MASQUERADE
    #iptables -A OUTPUT -p icmp -m owner --uid-owner $UIDTOR -j REJECT --reject-with icmp-net-prohibited
}

function lunch() {
		addr=`ip rule show | grep torvpn | head -n1 | awk '{print $5}'`
		BIND_ADDR=$addr LD_PRELOAD=/usr/lib/bind.so $*
}

function undertor() {
	cat /etc/proxychains.conf | sed "s/127.0.0.1 9050/127.0.0.1 9052/g" > ./proxychains.conf
	proxychains $*
	rm proxychains.conf
}

trap 'killOpFw; exit' SIGINT SIGQUIT SIGTERM
args=`getopt -l install,conf,newnym,openv,proxy,vpntor,torvpn,flush,kill,help,lunch,split,undertor :icnopvtfkhl:su $*`

if [ "$*" == "" ]; then
	help
fi

for i in $args; do
	case $i in
		-i|--install)
			install
		;;
		-c|--conf)
			shift;
			optarg=$1
			configure $optarg		
		;;
		-n|--newnym)
			shift;
			optarg=$*
			newnym $optarg
		;;
		-o|--openv)
			shift;
			optarg=$*
			openv $optarg
		;;
		-p|--proxy)
			trasparent_proxy
		;;
		-v|--vpntor)
			vpn_over_tor
		;;
		-t|--torvpn)
			tor_over_vpn
		;;
		-f|--flush)
			shift;
			optarg=$1
			flush $optarg
		;;
		-k|--kill)
			killOpFw
		;;
		-h|--help)
			help
		;;
		-l|--lunch)
			shift;
			optarg=$*
			lunch $optarg
		;;
		-s|--split)
			split_connection
		;;
		-u|--undertor)
			shift;
			optarg=$*
			undertor $optarg
		;;
	esac
done
