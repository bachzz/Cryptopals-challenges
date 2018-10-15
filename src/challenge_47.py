### EXPLAIN!

## Oracle (server): - Implement RSA to encrypt, decrypt messages
##					- Check PKCS1.5 valid padding of ciphertext
## Attacker: - Intercept a ciphertext
##			 - Use server's checking PKCS1.5 padding to crack the plaintext from ciphertext

## PKCS1.5:
##	00 || 02 || padding_string || 00 || data_block

## HOW? (this challenge is basically full of math instructions so I just follow the steps
##		more details below or follow this link: 
##		http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf)
	# Step 1: Blinding.
	# Step 2: Searching for PKCS conforming messages
		# 2.a: Start the search
		# 2.b: Searching with more than one interval left
		# 2.c: Searching with one interval left
	# Step 3: Narrowing the set of solutions

import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *
from Crypto import Random
from math import ceil

def pkcs_1_5_pad(message, key_byte_length):
    # Pads the given binary data conforming to the PKCS 1.5 format.
    padding_string = Random.new().read(key_byte_length - 3 - len(message)) # try os.urandom
    return b"\x00\x02" + padding_string + b"\x00" + message

class Oracle(RSA):
	def check_pkcs1_5_padding(self, ct_int):
		pt = self.decrypt_and_pad(ct_int)
		return len(pt) == ceil(self.n.bit_length(), 8) and pt[0] == "\x00" and pt[1] == "\x02"
	def decrypt_and_pad(self, ct_int):
		pt = self.decrypt(ct_int)
		return b"\x00" + pt

def ceil(a, b):
    return (a + b - 1) // b

def merge(intervals, lower_bound, upper_bound):
    # Adds a new interval to the list of intervals.
    for i, (a, b) in enumerate(intervals):
        # If there is an overlap, then replace the boundaries of the overlapping
        # interval with the wider (or equal) boundaries of the new merged interval
        if not (b < lower_bound or a > upper_bound):
            new_a = min(lower_bound, a)
            new_b = max(upper_bound, b)
            intervals[i] = new_a, new_b
            return
    intervals.append((lower_bound, upper_bound))

def pkcs_1_5_padding_oracle_attack(ciphertext, rsa_padding_oracle, key_byte_length, c_is_pkcs_conforming=True):
   	# Implementation from Bleichenbacher in CRYPTO '98: http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf

    # Set the starting values
    B = 2 ** (8 * (key_byte_length - 2))
    n, e = rsa_padding_oracle.n, rsa_padding_oracle.e   
    c_0 = ciphertext
    M = [(2 * B, 3 * B - 1)]
    i = 1

    if not rsa_padding_oracle.check_pkcs1_5_padding(c_0):
        # Step 1: Blinding
        while True:
            s = randint(0, n - 1)
            c_0 = (ciphertext * pow(s, e, n)) % n
            if rsa_padding_oracle.check_pkcs1_5_padding(c_0):
                break

    # Find the decrypted message through "several" iterations
    while True:
        # Step 2.a: Starting the search
        if i == 1:
            s = ceil(rsa_padding_oracle.n, 3 * B)#ceil(rsa_padding_oracle.n / (3 * B))#ceil(rsa_padding_oracle.n, 3 * B)
            while True:
                c = (c_0 * pow(s, e, n)) % n
                if rsa_padding_oracle.check_pkcs1_5_padding(c):
                    break
                s += 1

        # Step 2.b: Searching with more than one interval left
        elif len(M) >= 2:
            while True:
                s += 1
                c = (c_0 * pow(s, e, n)) % n
                if rsa_padding_oracle.check_pkcs1_5_padding(c):
                    break

        # Step 2.c: Searching with one interval left
        elif len(M) == 1:
            a, b = M[0]
            # Check if the interval contains the solution
            if a == b:
                # And if it does, return it as bytes
                return b'\x00' + hex_to_ascii("%x" % a)#int_to_bytes(a)
            r = ceil(2 * (b * s - 2 * B), n)
            s = ceil(2 * B + r * n, b)
            while True:
                c = (c_0 * pow(s, e, n)) % n
                if rsa_padding_oracle.check_pkcs1_5_padding(c):
                    break
                s += 1
                if s > (3 * B + r * n) // a:
                    r += 1
                    s = ceil((2 * B + r * n), b)

        # Step 3: Narrowing the set of solutions
        M_new = []
        for a, b in M:
            min_r = ceil(a * s - 3 * B + 1, n)
            max_r = (b * s - 2 * B) // n
            for r in range(min_r, max_r + 1):
                l = max(a, ceil(2 * B + r * n, s))
                u = min(b, (3 * B - 1 + r * n) // s)
                if l > u:
                    raise Exception('Unexpected error: l > u in step 3')
                merge(M_new, l, u)
        if len(M_new) == 0:
            raise Exception('Unexpected error: there are 0 intervals.')
        M = M_new
        i += 1


oracle = Oracle(256)

key_byte_length = int(ceil(oracle.n.bit_length(), 8))
message = b"kick it, CC"
message_padded = pkcs_1_5_pad(message, key_byte_length)
ct_int = oracle.encrypt(message_padded)
#print oracle.check_pkcs1_5_padding(ct_int)
#print oracle.n.bit_length()
pt = pkcs_1_5_padding_oracle_attack(ct_int, oracle, key_byte_length)
print pt

