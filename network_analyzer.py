import dpkt
import socket

def analyze_network_traffic(pkt):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data
    src_ip = socket.inet_ntoa(ip.src)
    dst_ip = socket.inet_ntoa(ip.dst)
    protocol = ip.p
    
    print('Source IP: {}'.format(src_ip))
    print('Destination IP: {}'.format(dst_ip))
    print('Protocol: {}'.format(protocol))

# create a raw socket
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

# receive packets on the socket
while True:
    pkt = s.recvfrom(65565)
    analyze_network_traffic(pkt[0])
