import socket,sys, struct
from struct import *
import psutil
import os

###########global vars
port = 65565

#this function is taken from https://github.com/jshreyans/sniffer/blob/master/sniffer_2.py
def get_mac_address(bytesString):
  '''
  returns the mac address
  '''
  bytesString = map('{:02x}'.format, bytesString)
  destination_mac = ':'.join(bytesString).upper()
  return destination_mac

def printTCP (packet):
    '''
    in this function we get the source port and destination port from the tcp header and print them
    '''
    ihl = 4 & 0xF
    iph_length = ihl * 4
    tcp_header = packet[iph_length:iph_length + 20]
    tcph = unpack('!HHLLBBHHH', tcp_header)

    source_port = tcph[0]
    dest_port = tcph[1]
    print("dest port for tcp: ", dest_port)
    print("source port for tcp: ", source_port)

def printProtocol (protocol, packet):
    '''gets the protocol number and prints the name'''
    switcher = {
        6: "TCP",
        115: "L2TP",
        199: "SRP",
        20: "HMP",
        14: "udp"
    }
    print("protocol: ", switcher.get(protocol, "not yet handled"))
    # for tcp protocol we print more information
    if protocol == 6 :
        printTCP(packet)

def printIPHInfo (iph):
    '''this function shows the information I found useful from IP header'''

    # the first parameter is the source address which we are gonna convert it to its mac address
    print("source addr: ", get_mac_address(iph[0]))

    # the second parameter is the destination destination which we are gonna convert it to its mac address
    print("destination addr: ", get_mac_address(iph[1]))

    print('Ethernet frame: ', iph[-1])


def main ():
    try:
      s = socket.socket(socket.AF_PACKET,
                        socket.SOCK_RAW,
                        socket.ntohs(3))
      print("socket created.")
    except socket.error:
      print('Socket could not be created.')

    while True:
        # listening on port 65565 and receiving the packet
        print("---------------------------------new packet--------------------------------------")
        packet = s.recvfrom(port)
        packet = packet[0]
        # unpacking ip header
        iph = struct.unpack('! 6s 6s H', packet[:14])
        printIPHInfo(iph)
        protocol = unpack('!BBHHHBBH4s4s', packet[0:20])[6]
        printProtocol(protocol, packet)

if __name__ == '__main__':
    main()


