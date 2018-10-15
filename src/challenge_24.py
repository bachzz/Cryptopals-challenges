### EXPLAIN!
## What we have?
	# Task 1: 
		# create a MT19937Cipher with a given key as seed to encrypt / decrypt a plaintext / ciphertext 
		# with only ciphertext, find the MT19937Cipher key using a known plaintext
	# Task 2:
		# create a token using MT19937RNG seeded with current time
		# write a function that checks whether a token is generated using MT19937RNG seeded with timestamp
## What to do?
	# Task 1:
		# create a MT19937Cipher class with encrypt / decrypt functions. encrypt() generates a keystream using MT19937RNG seeded with 16-bit key (repeatedly until keystream has the same length with plaintext)
		# Brute-force key from 0 - 2^16 until the decrypted plaintext contains the known-plaintext
	# Task 2:
		# same as 22

import sys
import time
import os

sys.path.insert(0, './lib')
from my_crypto_lib import *
from random import randint

class MT19937Cipher:
    
    def __init__(self, key):
        self.rng = MT19937RNG(key)
    
    def encrypt(self, plaintext):
        keystream = ""
        while len(keystream) < len(plaintext):
            keystream += str(self.rng.extract_number())
        ct = xor(keystream, plaintext)
        return ct
    
    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)

def find_MT19937Cipher_key(ciphertext, known_text):
	for key in range(0, 2**16):
		if known_text in MT19937Cipher(key).decrypt(ciphertext):
			return key
	return -1

def is_MT19937RNG_time_seeded(token, time_window = 500):
	seed_trial = int(time.time())
	seed_bound = seed_trial - time_window
	token_trial = MT19937RNG(seed_trial).extract_number()
	while token_trial != token and seed_trial >= seed_bound:
		seed_trial -= 1
		token_trial = MT19937RNG(seed_trial).extract_number()
	if token_trial == token:
		#print "Token found:",token_trial
		return True
	return False

key = randint(0, 2**16)
prefix = os.urandom(randint(0, 10))
text = "username=bachng"
plaintext = prefix + text

ct = MT19937Cipher(key).encrypt(plaintext)

key2 = find_MT19937Cipher_key(ct, text)
if key2 != -1:
	print "Key:", key2
	pt = MT19937Cipher(key2).decrypt(ct)
	print "Cookie:",pt
else:
	print "Key not found!"

print "\n"

seed = int(time.time())
password_reset_token = MT19937RNG(seed).extract_number()
print "Token:", password_reset_token

time.sleep(6) # simulate real time
if is_MT19937RNG_time_seeded(password_reset_token):
	print "=> Token was generated with MT19937RNG seeded with timestamp"
else:
	print "=> Undentified Token!"