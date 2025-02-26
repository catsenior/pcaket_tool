# Packet Modifier 
This script allows you to modify and replay pcap packets with adjustments to IP, MAC, and port information. It provides detailed packet information during transmission and supports TCP 3-way handshake for reliable replay.

## Features
Modify source and destination IP addresses, ports, and MAC addresses.
Replay packets through specified network interfaces.
Display detailed packet information, including Ethernet, IP, TCP, UDP, ICMP, and DNS layers.
Perform a TCP 3-way handshake before replaying packets.
Real-time packet sniffing and analysis with colorized output for better visibility.

## Requirements
Make sure you have the following Python packages installed:
```
pip install scapy colorama
```
## Usage
```
python3 packet_modifier.py -f <pcap_file> -nic1 <interface1> -nic2 <interface2> -sip <source_ip> -dip <destination_ip> -dport <destination_port> [-sport <source_port>] [-gw_mac <gateway_mac>] 
[-3w]
```
### Required Arguments:
```
-f, --file_path: Path to the pcap file to replay.

-nic1, --interface1: First network interface for sending packets.

-nic2, --interface2: Second network interface for receiving packets.

-sip, --src_ip: Source IP to modify.

-dip, --dst_ip: Destination IP to modify.

-dport, --dst_port: Destination port to modify.
```
### Optional Arguments:
```
-sport, --src_port: Source port to modify (if not specified, use the original value from the pcap).

-gw_mac, --gateway_mac: Gateway MAC address (if different from the destination MAC).

-3w, --handshake: Perform TCP 3-way handshake before sending packets.
```
## Example Commands
### Basic Usage
Replay a pcap file, modifying the source and destination IPs and destination port:
```
sudo python3 packet_modifier.py -f capture.pcap -nic1 eth0 -nic2 eth1 -sip 192.168.1.100 -dip 192.168.1.200 -dport 80
```
### Specify Source Port
```
sudo python3 packet_modifier.py -f capture.pcap -nic1 eth0 -nic2 eth1 -sip 192.168.1.100 -dip 192.168.1.200 -sport 12345 -dport 80
```
### Perform TCP 3-Way Handshake
```
sudo python3 packet_modifier.py -f capture.pcap -nic1 eth0 -nic2 eth1 -sip 192.168.1.100 -dip 192.168.1.200 -dport 80 -3w
```
### Set Gateway MAC Address
```
sudo python3 packet_modifier.py -f capture.pcap -nic1 eth0 -nic2 eth1 -sip 192.168.1.100 -dip 192.168.1.200 -dport 80 -gw_mac 00-11-22-33-44-55
```
## How It Works
### Packet Capture and Display:

Captures packets from the specified network interface.
Displays detailed layer information, including Ethernet, IP, TCP, UDP, ICMP, and DNS layers.
Uses colorama for colorized terminal output.
### Packet Modification:

Adjusts the source and destination IPs, ports, and MAC addresses.
Recalculates checksums to maintain packet integrity.
Supports Gateway MAC adjustment for routing scenarios.
### Packet Replay:

Sends the modified packets through the specified network interface.
Displays success or error messages based on capture and replay results.

### TCP 3-Way Handshake (Optional):

Initiates a 3-way handshake before replaying TCP packets to maintain connection states.

## Dependencies
scapy: For packet manipulation and replay.
colorama: For colorful console output.

Install them using:
```
pip install scapy colorama
```
## Notes
Run the script with root privileges to access network interfaces:
```
sudo python3 packet_retry_tool.py ...
```
Ensure the network interfaces are correctly configured for packet capture and replay.


