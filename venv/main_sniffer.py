import socket,sys,struct

# create a network socket using the default constructor
try:
  sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
except socket.error:
  print('Socket could not be created.')
  sys.exit(1)