### EXPLAIN!!

## WHAT WE HAVE?
	# An oracle - a service that encrypt a text = prefix || our input || postfix using AES in CTR mode, then return ciphertext
	# That oracle will clean ";", "=" from our input
	# That oracle also provide decrypt() to decrypt ciphertext
## GOAL?
	# Make output of oracle's decrypt() produce a text include ";admin=true"
## HOW?
	# Step 1: get ciphertext prefix size => append ADMIN ciphertext (C2) after that
		# Encrypt two different ciphertexts
		# Since the stream ciphers encrypts bit by bit, the prefix length will be equal to
		# the number of bytes that are equal in the two ciphertext.
	# Step 2: create ADMIN ciphertext 
		# We can get ciphertext C1:		C1 XOR keystream = "?admin?true"	(1)
		# We want to get ciphertext C2: C2 XOR keystream = ";admin=true"	(2)
		# (1) XOR (2) =>	C1 XOR C2 = "?admin?true" XOR ";admin=true"		(3)
		# C1 XOR  (3) =>	C2 = C1 XOR "?admin?true" XOR ";admin=true"
		# EVIL ciphertext = ciphertext(prefix) + C2 + ciphertext(postfix)
		# => Now decrypt EVIL ciphertext to get ADMIN privilege!!

import sys
sys.path.insert(0, './lib')
from my_crypto_lib import *

import os
from random import randint

class Oracle:
	def __init__(self):
		self.key = "YELLOW SUBMARINE"#os.urandom(16)
		self.nonce = "\x00"

	def generate_token(self, input_string):
		input_string=input_string.replace(";","").replace("=","")
		string="comment1=cooking%20MCs;userdata="+input_string+";comment2=%20like%20a%20pound%20of%20bacon"
		#string=pkcs7_padding(string)
		#string_enc=aes_cbc_enc(128,string,key,iv)
		string_enc = aes_ctr_enc(string, self.key, self.nonce)
		#return hex_to_ascii(string_enc)
		return string_enc

	def decrypt(self, ciphertext):
		return aes_ctr_dec(ciphertext, self.key, self.nonce)

	def check_admin(self, ciphertext):
		return ";admin=true" in self.decrypt(ciphertext)

def get_prefix_length(oracle):
	"""Finds the length of the prefix added to the plaintext before encrypting."""
	# Encrypt two different ciphertexts
	ciphertext_a = oracle.generate_token(b'A')
	ciphertext_b = oracle.generate_token(b'B')
	
	# Since the stream ciphers encrypts bit by bit, the prefix length will be equal to
	# the number of bytes that are equal in the two ciphertext.
	prefix_length = 0
	while ciphertext_a[prefix_length] == ciphertext_b[prefix_length]:
		prefix_length += 1
	return prefix_length

def make_admin(oracle):
	"""Performs a stream cipher bit flipping attack to accomplish admin privileges in the decrypted data."""
	plaintext = b'?admin?true'
	ciphertext = oracle.generate_token(plaintext)

    # Prepare the data with which we want to XOR our goal ciphertext substring
	goal_text = b';admin=true'
	insert = xor(plaintext, goal_text)

    # Find the position where our goal ciphertext substring starts
	prefix_length = get_prefix_length(oracle)

    # Force our goal ciphertext block to be the encryption of our goal text
	forced_ciphertext = ciphertext[:prefix_length] + \
                        xor(ciphertext[prefix_length:prefix_length + len(plaintext)], insert) + \
                        ciphertext[prefix_length + len(plaintext):]

	return forced_ciphertext


oracle = Oracle()

ct = make_admin(oracle)
print oracle.decrypt(ct)
if oracle.check_admin(ct):
	print "Welcome back, ADMIN!"
else:
	print "Welcome back, USER!"