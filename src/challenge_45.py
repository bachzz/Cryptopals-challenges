### EXPLAIN!!!

## If g = p + 1 or g = 0 => r = (g ^ k) mod p = 1 for ALL k
## => same signature can be verified for different messages

import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *

p = int('800000000000000089e1855218a0e7dac38136ffafa72eda7'
	     				'859f2171e25e65eac698c1702578b07dc2a1076da241c76c6'
	     				'2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe'
	     				'ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2'
	     				'b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87'
	     				'1a584471bb1', 16)
q = int('f4f47f05794b256174bba6e9b396a7707e563c5b', 16)

# NOTE: my DSA implementation psuedocode's is from https://en.wikipedia.org/wiki/Digital_Signature_Algorithm
# So my DSA oracle will run forever with g = 0 => I skip to g = p + 1 

### CHANGE g HERE ###
g = p + 1		    #
#####################

dsa = DSA(p, q, g)

message = b"Hello, world"
message2 = b"Goodbye, world"
r, s = dsa.sign(message)

print "DSA with g = p + 1\n"
print "'Hello, world''s signature:"
print "=> r = ", r
print "=> s = ", s
print "Verifying 'Hello, world' using r, s..."
if dsa.verify(message, r, s):
	print "=> Accepted!"
print "Verifying 'Goodbye, world' using r, s..."
if dsa.verify(message2, r, s):
	print "=> Accepted!"

# question: what about s? why s = (r / z) mod q (with z arbitrary)