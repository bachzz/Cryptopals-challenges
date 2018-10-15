### Same as 31 but add normalization method for more accuracy
### NOTE: Run challenge_31_server.py before attack

import web
import sys
import requests
import time

sys.path.insert(0, './lib')
from my_crypto_lib import *
from statistics import median

HMAC_LEN = 20

def get_next_byte(known_bytes, filename, rounds):
	l = len(known_bytes)
	max_time = 0
	byte = ''
	times = [0 for i in range(16)]
	for j in range(rounds+1):
		for i in range(16):
			sig_test = known_bytes + hex(i)[2:] + "\x00" * (HMAC_LEN * 2 - l)
			start = time.time()
			response = requests.get('http://localhost:8888/test?file=' + filename + '&signature=' + sig_test)
			end = time.time()
			times[i] += end - start
	times = [i / rounds for i in times]
	max_i = times.index(max(times))
	byte = hex(max_i)[2:]
	return byte

def discover_mac_with_timing_attack(filename, rounds):
    """Performs a timing attack on the HMAC server."""
    print("Timing attack started.")

    # Get the HMAC byte by byte
    known_bytes = b''
    while len(known_bytes) < HMAC_LEN * 2: # x2 for hex length
        known_bytes += get_next_byte(known_bytes, filename, rounds)
        print "Discovered so far: " + known_bytes
    return known_bytes
	

# correct signature for "foo" = "f108c40b86dbb203831d437d81b5d9a9f827157b"
filename = "foo"
signature = discover_mac_with_timing_attack(filename, 10)
response = requests.get('http://localhost:8888/test?file=' + filename + '&signature=' + signature)

if response.status_code == 200:
	print "\nWe made it! The HMAC is:" + signature
else:
	print "\nUnfortunately the attack did not work."