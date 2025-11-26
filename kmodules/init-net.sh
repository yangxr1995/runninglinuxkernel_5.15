ip route del default
ip route add default via 172.168.12.1 dev eth0
tc qdisc add dev eth0 root fq
