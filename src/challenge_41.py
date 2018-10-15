### EXPLAIN!!

## The Oracle (server) provides service to encrypt user's message and decrypt ciphertexts (NOT in database)
## The attacker can ask for the encryption and decryption of anything he/she wants - except user's ciphertexts which are in database
## => Goal: Attacker recover user's message from its ciphertext using decryption service of server
##
## How? 
## In Unpadded RSA,  if operations like multiplication and addition are carried out on ciphertext, 
## it is as if the same operation were applied to the plaintext
## => The attacker can't ask for the decryption of user's ciphertext, but attacker can ask for the decryption of ciphertext_2 
## and attacker knows that the result will be plaintext_2. 
## => Just divide out the scaling factor, and attacker has the plaintext.


import time
import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *
from random import randint

class Oracle():
	def __init__(self):
		self.total = 0
		self.size = 10
		data = {"timestamp": 0, "ct_int": 0}
		self.db = [data for i in range(self.size)]
		self.cipher = RSA(1024)
	def get_public_key(self):
		result = {"n": self.cipher.n, "e": self.cipher.e}
		return result
	def check_ct_int(self, ct_int):
		# check current ciphertext already in database or not
		for i in range(self.size):
			if self.db[i]["ct_int"] == ct_int:
				return True
		return False
	def encrypt(self, message):
		# every time server encrypts message for an user, a new timestamp is tagged into the ciphertext
		# then return ciphertext to user
		ct_int = self.cipher.encrypt(message)
		data = {"timestamp": int(time.time()), "ct_int": ct_int}
		self.db[self.total] = data
		self.total += 1
		return ct_int
	def decrypt(self, ct_int):
		if self.check_ct_int(ct_int):
			raise Exception("Ciphertext is already in database!")
		else:
			return self.cipher.decrypt(ct_int)

def recover_message(oracle, ct_int):
	# Capture public key
	n = oracle.get_public_key()["n"]
	e = oracle.get_public_key()["e"]
	# Get s such that s > 1 mod n
	while True:
		s = randint(2, n-1)
		if s % n > 1:
			break
	# ct_int2 = ( (s**e mod n) * c ) mod n
	ct_int2 = (pow(s, e, n) * ct_int) % n
	# get pt2 corresponding to ct2 (which isn't in database)
	pt2_int = int(ascii_to_hex(oracle.decrypt(ct_int2)), 16)
	# original plaintext of ct_int
	pt_int = (pt2_int * inv_mod(s, n)) % n
	pt_hex = "%x" % pt_int
	return hex_to_ascii(pt_hex)

oracle = Oracle()
message = "Privacy is just a myth."
print "User's message:", message
# Capture ciphertext
ct_int = oracle.encrypt(message)
print "Ciphertext:", ct_int
plaintext = recover_message(oracle, ct_int)
print "Cracked plaintext:", plaintext