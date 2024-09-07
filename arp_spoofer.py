#!/usr/bin/python3

from uuid import getnode as get_mac
from struct import pack
from socket import socket, AF_PACKET, SOCK_RAW, PACKET_BROADCAST

#<config
INTERFACE = 'wlp3s0'

#>


ONE_BYTE = '!B'
TWO_BYTES = '!H'


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


def create_arp_payload(sender_ip, target_ip):
    hardware_type = 0x0001       # for ethernet
    protocol_type = 0x0800       # for ipv4
    hardware_address_len = 0x06  # for mac
    protocol_address_len = 0x04  # for ipv4
    operation = 0x0001           # for 'send'
    sender_hardware_address = split_mac(get_mac())
    sender_protocol_address = split_ip(sender_ip)
    target_hardware_address = 0x0000 # ignored for 'send'
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

        pack(TWO_BYTES, target_hardware_address),
        pack(TWO_BYTES, target_hardware_address),
        pack(TWO_BYTES, target_hardware_address),

        pack(TWO_BYTES, target_protocol_address[0]),
        pack(TWO_BYTES, target_protocol_address[1])])


def create_eth_header():
    destination = split_mac(0xffffffffffff) # broadcast
    source = split_mac(get_mac())
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


def create_arp_packet(sender_ip, target_ip):
    return b''.join([
                     create_eth_header(),
                     create_arp_payload(sender_ip, target_ip)]) 


def send(packet):
    with socket(AF_PACKET, SOCK_RAW) as s:
        s.bind((INTERFACE, 0, PACKET_BROADCAST))
        s.send(packet)


send(create_arp_packet('192.168.1.190', '192.168.1.1'))
