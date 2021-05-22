#Command to test:
#python3 main.py -n 192.168.0.0/24 -p 80,443

import socket
import scapy.all as scapy
import argparse

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--network', dest='network', help='Network with mask to scann')
    parser.add_argument('-p', '--port', dest='port', help='Ports to scann')
    options = parser.parse_args()

    if not options.network:
        parser.error("[-] Please specify an IP Address or Addresses, use --help for more info.")
    return options

def scan(ip):
    arp_req_frame = scapy.ARP(pdst=ip)

    broadcast_ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame

    answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout=1, verbose=False)[0]
    result = []
    for i in range(0, len(answered_list)):
        client_dict = {"ip": answered_list[i][1].psrc, "mac": answered_list[i][1].hwsrc}
        result.append(client_dict)

    return result

def scanPort(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        print("Port open: " + str(port))
        s.close()
    except:
        print("Port closed: " + str(port))


def display_result(result, input):
    print("-----------------------------------\nIP Address\tMAC Address\n-----------------------------------")
    for i in result:
        print("{}\t{}".format(i["ip"], i["mac"]))
        ports = str(input).split(',')
        for port in ports:
            scanPort(i["ip"],port)


options = get_args()
scanned_output = scan(options.network)
display_result(scanned_output, options.port)



print("done")