### NOTE: USE PYTHON3 for this challenge!! python2 doesn't give correct result, I'll look into it when I have time.

### EXPLAIN!!

## When messages are signed using DSA with repeated nonce (r, k),
## given a pair of messages, attacker can find k using the formula:
##			(m1 - m2)
##		k = --------- mod q
##			(s1 - s2)

## Proof! (mathematically)
	# private key formula: x = (s1 * k) - m1 * inv_mod(r1,q) mod q
	#					   x = (s2 * k) - H(messa * inv_mod(r2,q) mod q
	#					   if r1 == r2:
	#					   => k = (m1 - m2) / (s1 - s2) mod q	
## We have k => We have x! (same as challenge 43)

import re
import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *


def parse_data():
    """Parses the input file and returns an array containing (s, r, m) of each signature."""
    #pattern = r'msg: [a-zA-Z.,\' ]+\n' \
    pattern = r's: ([0-9]+)\n' \
              r'r: ([0-9]+)\n' \
              r'm: ([0-9a-f]+)\n?'

    f = open('./txt/44.txt')
    t = f.read()
    f.close()

    return re.findall(pattern, t)

def find_private_key_with_repeated_k(dsa, data):
	for i in range(0, len(data) - 1):
		#print len(data)
		j = i + 1
		r1 = int(data[i][1])
		#print r1
		r2 = int(data[j][1])
		while r2 != r1:
			#print r1-r2
			j += 1
			r2 = int(data[j][1])

		m1 = int(data[i][2], 16)
		m2 = int(data[j][2], 16)
		s1 = int(data[i][0])
		s2 = int(data[j][0])
		k = (((m1 - m2) % dsa.q) * inv_mod((s1 - s2) % dsa.q, dsa.q)) % dsa.q
		x = (((s1 * k) - m1) * inv_mod(r1, dsa.q)) % dsa.q
		return x 

dsa = DSA()
data = parse_data()
private_key = find_private_key_with_repeated_k(dsa, data)
c = hex(private_key)[2:].encode()
print ("SHA-1 fingerprint:", sha1(c))
assert sha1(c) == "ca8f6f7c66fa362d40760d135b763eb8527d3d52"

