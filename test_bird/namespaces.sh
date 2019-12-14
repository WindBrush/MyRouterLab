# pc1-r1-r2-r3-pc2

# create namespaces. Names follow the convention of documentation of Router Lab

ip netns add pc1

ip netns add r1

ip netns add r2

ip netns add r3

ip netns add pc2

# link the virtual ethernet interfaces

# specifically, the ip of interfaces of [r2] are omitted.

# link [pc1] and [r1]

ip link add veth-pc1-r1 type veth peer name veth-r1-pc1

ip link set veth-pc1-r1 netns pc1

ip link set veth-r1-pc1 netns r1

ip netns exec pc1 ip link set veth-pc1-r1 up

ip netns exec pc1 ip addr add 192.168.1.2/24 dev veth-pc1-r1

ip netns exec r1 ip link set veth-r1-pc1 up

ip netns exec r1 ip addr add 192.168.1.1/24 dev veth-r1-pc1

# link [r1] and [r2]

ip link add veth-r1-r2 type veth peer name veth-r2-r1

ip link set veth-r1-r2 netns r1

ip link set veth-r2-r1 netns r2

ip netns exec r1 ip link set veth-r1-r2 up

ip netns exec r1 ip addr add 192.168.3.1/24 dev veth-r1-r2

ip netns exec r2 ip link set veth-r2-r1 up

# link [r2] and [r3]

ip link add veth-r2-r3 type veth peer name veth-r3-r2

ip link set veth-r2-r3 netns r2

ip link set veth-r3-r2 netns r3

ip netns exec r2 ip link set veth-r2-r3 up

ip netns exec r3 ip link set veth-r3-r2 up

ip netns exec r3 ip addr add 192.168.4.2/24 dev veth-r3-r2

# link [r3] and [pc2]

ip link add veth-r3-pc2 type veth peer name veth-pc2-r3

ip link set veth-r3-pc2 netns r3

ip link set veth-pc2-r3 netns pc2

ip netns exec r3 ip link set veth-r3-pc2 up

ip netns exec r3 ip addr add 192.168.5.2/24 dev veth-r3-pc2

ip netns exec pc2 ip link set veth-pc2-r3 up

ip netns exec pc2 ip addr add 192.168.5.1/24 dev veth-pc2-r3

# add needed route entry

ip netns exec pc1 ip route add default via 192.168.1.1 dev veth-pc1-r1

ip netns exec pc2 ip route add default via 192.168.5.2 dev veth-pc2-r3

# configure forwarding

ip netns exec r1 sysctl -w net.ipv4.ip_forward=1

ip netns exec r2 sysctl -w net.ipv4.ip_forward=0

ip netns exec r3 sysctl -w net.ipv4.ip_forward=1
