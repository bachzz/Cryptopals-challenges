### EXPLAIN!
## WHAT WE HAVE?
	# An insecure oracle provides
		#- a service that encrypts prefix || messages || postfix in CBC mode with IV = key
		#- a service to decrypt ciphertext + check ADMIN privilege + check if all characters in a plaintext are ASCII compliant (in ASCII table - printable), if not, will show exception and return the corrupted text
## GOAL?
	# Get the hidden key from oracle
## HOW?
	# Basically, send 3 blocks ( block_size = 16 (AES) ) of ciphertext to oracle's service - check admin: 
		# CT = C1 || "\x00" * block_size || C1 
		# oracle decrypts plaintext: PT = iv XOR dec(C1) || ........ || "\x00 * block_size" XOR dec(C1)
		#								  ---- P1 ------    -- P2 --	------------ P3 ---------------
		# oracle returns corrupted PT from exception to attacker
		# Attacker computes: P1 XOR P3 = iv XOR "\x00 * block_size" = iv = key
	# Details of the process are in cryptopals' description (not sure why we need to modify ciphertext when we can generate one, it still works)


import sys
import os


sys.path.insert(0, './lib')
from my_crypto_lib import *
from random import randint


class Oracle:
	def __init__(self):
		self.key = os.urandom(16)
		self.iv = self.key

	def generate(self, input_string):
		intput_string=input_string.replace(";","").replace("=","")
		string="comment1=cooking%20MCs;userdata="+input_string+";comment2=%20like%20a%20pound%20of%20bacon"
		string=pkcs7_padding(string)
		string_enc=aes_cbc_enc(128,string,self.key,self.iv)
		return hex_to_ascii(string_enc)

	def check_ascii_compliance(self, plaintext):
		"""A service - returns true if all the characters of plaintext are ASCII compliant (ie are in the ASCII table)."""
		return all(c < 128 for c in plaintext)

	def check_admin(self, ciphertext):
		plaintext=aes_cbc_dec(128,ciphertext,self.key,self.iv) 
		if not self.check_ascii_compliance(plaintext):
			# Take advantage of check_ascii_compliance() to get the corrupted plaintext for latter use
			raise Exception("The message is not valid", plaintext)
		return ";admin=true;" in plaintext	

def get_key_from_insecure_cbc(encryption_oracle):
	"""Recovers the key from the lazy encryption oracle using the key also as iv.
	The approach used is the simple one outlined in the challenge description.
	"""
	block_length = find_block_length(encryption_oracle.generate)
	prefix_length = find_prefix_length(encryption_oracle.generate, block_length)

	# Create three different blocks of plaintext and encrypt their concatenation
	p_1 = 'A' * block_length
	p_2 = 'B' * block_length
	p_3 = 'C' * block_length
	ciphertext = encryption_oracle.generate(p_1 + p_2 + p_3)

	# Force the ciphertext to be "C_1, 0, C_1"
	forced_ciphertext = ciphertext[prefix_length:prefix_length + block_length] + b'\x00' * block_length + \
	                    ciphertext[prefix_length:prefix_length + block_length]
	# Expect an exception from the lazy oracle
	try:
		encryption_oracle.check_admin(forced_ciphertext)
	except Exception as e:
		forced_plaintext = e.args[1]

		# Compute the key and return it
		# The first block of the plaintext will be equal to (decryption of c_1 XOR iv).
		# The last block of the plaintext will be equal to (decryption of c_1 XOR 0).
 		# Therefore, to get the iv (which we know is equal to the key), we can just
		# xor the first and last blocks together.
		return xor(forced_plaintext[:block_length], forced_plaintext[-block_length:])
	raise Exception("Was not able to hack the key")


encryption_oracle = Oracle()
hacked_key = get_key_from_insecure_cbc(encryption_oracle)
# Check that the key was recovered correctly
assert encryption_oracle.key == hacked_key
print "Hidden key:\t\t\t\t\t", encryption_oracle.key
print "Cracked key from insecure CBC (iv == key):\t", hacked_key