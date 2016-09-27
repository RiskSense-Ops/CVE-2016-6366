#!/usr/bin/env python2

import sys
import binascii

data = open(sys.argv[1], "rb").read()
hex = []
for c in data:
    hex.append(binascii.hexlify(c))

print "\\x" + "\\x".join(hex)
print

str = ""
for c in hex:
    str += "%d." % int(c, 16)

print str[:-1]
