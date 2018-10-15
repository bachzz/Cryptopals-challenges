### EXPLAIN!
## WHAT WE HAVE?
	# A server: 
		# handles request: "http://localhost:8888/test?file=XXX&signature=XXX" || client inputs XXX
		# Validate the digest of filename with the signature (insecurely) by checking byte-by-byte with delay time and stops at incorrect byte
	# A client:
		# Recover the digest byte-by-byte with timing attack
## GOAL?
	# Recover the digest byte-by-byte with timing attack
## HOW?
	# Iterate through all possible bytes (0 - 15 <=> 0 - F), making a request with my known bytes + byte_guess + padding.
	# Take the maximum delay each time, which would occur when I've guessed the byte correctly, causing another sleep of 50ms, for an added delay of 100ms.
	# The byte with maximum delay each time is the correct byte for a position in digest
	# Append that byte to known bytes (found bytes) and brute-force next byte
## NOTE:
    # Run challenge_31_server.py before attack

import web
import sys
import requests
import time

sys.path.insert(0, './lib')
from my_crypto_lib import *
from statistics import median

HMAC_LEN = 20

def get_next_byte(known_bytes, filename):
	l = len(known_bytes)
	max_time = 0
	byte = ''
	for i in range(16):
		sig_test = known_bytes + hex(i)[2:] + "\x00" * (HMAC_LEN * 2 - l)
		start = time.time()
		response = requests.get('http://localhost:8888/test?file=' + filename + '&signature=' + sig_test)
		end = time.time()
		if end - start >= max_time:
			max_time = end - start
			byte = hex(i)[2:]
	return byte

def discover_mac_with_timing_attack(filename):
    """Performs a timing attack on the HMAC server."""
    print("Timing attack started.")

    # Get the HMAC byte by byte
    known_bytes = b''
    while len(known_bytes) < HMAC_LEN * 2: # x2 for hex length
        known_bytes += get_next_byte(known_bytes, filename)
        print "Discovered so far: " + known_bytes
    return known_bytes
	

# correct signature for "foo" = "f108c40b86dbb203831d437d81b5d9a9f827157b"
filename = "foo"
signature = discover_mac_with_timing_attack(filename)
response = requests.get('http://localhost:8888/test?file=' + filename + '&signature=' + signature)

if response.status_code == 200:
	print "\nWe made it! The HMAC is:" + signature
else:
	print "\nUnfortunately the attack did not work."