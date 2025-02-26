import argparse
import sys
import os
import time
from scapy.all import *
from colorama import Fore, Style
packet_num = 1
def _display_packet(pkt):
    global packet_num
    indent_str = " " * 4
    print("\n[>>>] Waiting for incoming data.\n")
    print(f"----- Packet Info -----\n")
    print(f"{Fore.GREEN}Packet Num: {packet_num}{Style.RESET_ALL}")
    packet_num += 1
    if pkt.haslayer(Ether):
        print(f"[+] Ethernet Layer:")
        print(f"{indent_str}Ethernet: {pkt[Ether].src} -> {pkt[Ether].dst}")
    
    if pkt.haslayer(IP):
        print(f"[+] IP Layer:")
        print(f"{indent_str}IP Version: {pkt[IP].version}")
        print(f"{indent_str}IP: {pkt[IP].src} -> {pkt[IP].dst}")
    
    if pkt.haslayer(TCP):
        print(f"[+] TCP Layer:")
        print(f"{indent_str}Port: {pkt[TCP].sport} -> {pkt[TCP].dport}")
        print(f"{indent_str}Flags: {pkt[TCP].flags}")

    if pkt.haslayer(UDP):
        print(f"[+] UDP Layer:")
        print(f"{indent_str}UDP: {pkt[UDP].sport} -> {pkt[UDP].dport}")
    
    if pkt.haslayer(ICMP):
            print(f"[+] ICMP Layer:")
            print(f"{indent_str}Type: {pkt[ICMP].type}, Code: {pkt[ICMP].code}")
 
    if pkt.haslayer(DNS):
        print(f"[+] DNS Layer:")
        if pkt.haslayer(DNSQR):
            print(f"{indent_str}Query: {pkt[DNSQR].qname.decode()}")
        if pkt.haslayer(DNSRR):
            print(f"{indent_str}Response: {pkt[DNSRR].rdata}")

def sniff_and_send(received_nic, send_nic, pkt):
    sniffer = AsyncSniffer(iface=received_nic,
                        filter=f'ip host {nic1_ip}',
                        prn=_display_packet, 
                        count=10,
                        timeout=1)
    sniffer.start()

    time.sleep(0.1)

    print(f'\n[>>>] Sending packet through {send_nic}')
    sent_tcp_flags = pkt[TCP].flags if TCP in pkt else None # Check captured_tcp_flags
    sendp(pkt, iface=send_nic, verbose=False)

    sniffer.join()
    results = sniffer.results
    
    if results is None or len(results) == 0:
        print(f'\n{Fore.RED}::: No packets captured on {received_nic} :::{Style.RESET_ALL}\n')
        print(f'\n{Fore.RED}Packets may be blocked by firewall or did not reach the target interface{Style.RESET_ALL}\n')
    else:
        if sent_tcp_flags is not None:
            for captured_pkt in results:
                if TCP in captured_pkt:
                    captured_tcp_flags = captured_pkt[TCP].flags
                    if sent_tcp_flags != captured_tcp_flags:
                        print(f'{Fore.RED}TCP Flags mismatch:')
                        print(f'Sent TCP Flags: {sent_tcp_flags}')
                        print(f'Received TCP Flags: {captured_tcp_flags}{Style.RESET_ALL}')
                    else:
                        print(f'\n::: {received_nic}{Fore.YELLOW} successfully{Style.RESET_ALL} captured packet :::\n')

def modify_packet(pkt, src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac, gw_mac=None):
    if TCP in pkt or UDP in pkt:
        proto_layer = pkt[TCP] if TCP in pkt else pkt[UDP]
        proto_layer.sport = src_port
        proto_layer.dport = dst_port
    
    if IP in pkt:
        pkt[IP].src = src_ip
        pkt[IP].dst = dst_ip

    if Ether in pkt:
        pkt[Ether].src = src_mac
        pkt[Ether].dst = gw_mac.replace('-',':') if gw_mac else dst_mac

    del pkt[IP].chksum
    if TCP in pkt:
        del pkt[TCP].chksum
    elif UDP in pkt:
        del pkt[UDP].chksum

    print(f"\n[>>>] Starting to send packet:")
    print(f"{src_ip} => {dst_ip}")
    print(f'\t{pkt}', flush=True)

    return pkt


parser = argparse.ArgumentParser(description="Modify and replay pcap packets with IP, MAC, and port adjustments.")
parser.add_argument("-f", "--file_path", type=str,dest='file_path', required=True, help="Path to the pcap file to replay")
parser.add_argument("-nic1", "--interface1", dest='nic1', required=True, help="First network interface")
parser.add_argument("-nic2", "--interface2", dest='nic2', required=True, help="Second network interface")
parser.add_argument("-sip", "--src_ip", type=str, dest='sip', required=True, help="Source IP to modify")
parser.add_argument("-dip", "--dst_ip", type=str, dest='dip', required=True, help="Destination IP to modify")
parser.add_argument("-sport", "--src_port", type=int, dest='sport', required=False, help="Source port to modify")
parser.add_argument("-dport", "--dst_port", type=int, dest='dport', required=True, help="Destination port to modify")
parser.add_argument("-gw_mac", "--gateway_mac", type=str, dest='gw_mac', required=False, help="Router's MAC address")
parser.add_argument("-3w","--handshake", dest='handshake', required=False, action='store_true', help="Perform TCP 3-way handshake before sending packets")


args = parser.parse_args()

pkts = rdpcap(args.file_path)

nic1 = args.nic1
nic2 = args.nic2

nic1_ip = args.sip
nic2_ip = args.dip

src_ip_from_first_pcap = pkts[0][IP].src
dest_ip_from_first_pcap = pkts[0][IP].dst

mac1 = get_if_hwaddr(nic1)
mac2 = get_if_hwaddr(nic2)

src_ip_from_first_pcap = pkts[0][IP].src
dest_ip_from_first_pcap = pkts[0][IP].dst

if pkts[0].haslayer(TCP):
    client_port = args.sport if args.sport else pkts[0][TCP].sport
    server_port = args.dport
    if args.handshake:
        # 3-way handshake
        sample_first_seq = pkts[0][TCP].seq
        sample_first_ack = pkts[0][TCP].ack
        # SYN
        syn_pkt = Ether(src= mac1, dst= mac2) / IP(src= nic1_ip, dst= nic2_ip) / TCP(sport= client_port, dport= server_port, flags='S',seq = (sample_first_seq - 1), ack = 0)
        sendp(syn_pkt, iface= nic1)
        # SYN ACK
        syn_ack_pkt = Ether(src= mac2, dst= mac1) / IP(src= nic2_ip, dst= nic1_ip) / TCP(sport= server_port, dport= client_port, flags='SA', seq = (sample_first_ack - 1), ack =  sample_first_seq)
        sendp(syn_ack_pkt, iface= nic2)
        # ACK
        ack_pkt = Ether(src= mac1, dst= mac2) / IP(src= nic1_ip, dst= nic2_ip) / TCP(sport= client_port, dport= server_port, flags='A',seq = sample_first_seq, ack = sample_first_ack)
        sendp(ack_pkt, iface= nic1)
elif pkts[0].haslayer(UDP):
    client_port = args.sport if args.sport else pkts[0][UDP].sport
    server_port = args.dport

for pkt in pkts:
    packet_params = {
        'pkt': pkt,
    }
    
    if pkt[IP].src == src_ip_from_first_pcap:
        send_nic, received_nic = nic1, nic2
        packet_params.update({
            'src_ip': nic1_ip,
            'dst_ip': nic2_ip,
            'src_port': client_port,
            'dst_port': server_port,
            'src_mac': mac1,
            'dst_mac': mac2,
        })
    elif pkt[IP].src == dest_ip_from_first_pcap:
        send_nic, received_nic = nic2, nic1
        packet_params.update({
            'src_ip': nic2_ip,
            'dst_ip': nic1_ip,
            'src_port': server_port,
            'dst_port': client_port,
            'src_mac': mac2,
            'dst_mac': mac1,
        })
    
    if args.gw_mac:
        packet_params['gw_mac'] = args.gw_mac
        
    pkt = modify_packet(**packet_params)
    sniff_and_send(received_nic, send_nic, pkt)
