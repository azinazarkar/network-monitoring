import socket,sys, struct
from struct import *
import psutil
import os

# create a network socket using the default constructor
try:
  s = socket.socket(socket.AF_PACKET,
                    socket.SOCK_RAW,
                    socket.ntohs(3))
  print("socket created!!")
except socket.error:
  print('Socket could not be created.')

# this function is taken from https://github.com/jshreyans/sniffer/blob/master/sniffer_2.py
def get_mac_address(bytesString):
  bytesString = map('{:02x}'.format, bytesString)
  destination_mac = ':'.join(bytesString).upper()
  return destination_mac

while True:

    # listening on port 65565 and receiving the packet
    packet = s.recvfrom(65565)
    packet = packet[0]
    # unpacking ip header
    iph = struct.unpack('! 6s 6s H', packet[:14])
    # the first parameter is the source address which we are gonna convert it to its mac address
    print("source addr: ", get_mac_address(iph[0]))
    # the second parameter is the destination destination which we are gonna convert it to its mac address
    print("destination addr: ", get_mac_address(iph[1]))
    data = packet[14:]
    print('Ethernet frame: ', iph[-1])
    protocol = iph = unpack('!BBHHHBBH4s4s', packet[0:20])[6]
    # print('protocol: ', protocol)
    switcher = {
        6: "TCP",
        115: "L2TP",
        199: "SRP",
        20: "HMP",
        14: "udp"
    }
    print("protocol: ", switcher.get(protocol, "not yet handled"))
    if protocol == 6 :
        ihl = 4 & 0xF
        iph_length = ihl * 4
        tcp_header = packet[iph_length:iph_length + 20]
        tcph = unpack('!HHLLBBHHH', tcp_header)

        source_port = tcph[0]
        dest_port = tcph[1]
        print("dest port for tcp: ", dest_port)
        print("source port for tcp: ", source_port)
