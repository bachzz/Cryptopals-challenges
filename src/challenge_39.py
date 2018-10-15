### EXPLAIN!
### RSA
	## Basic of RSA is about to find 3 prime numbers e, d, n (n - very large prime) such that for all m (0 < m <n)
	##		(m ^ e) ^ d = m (mod n)
	##	NOTE: even knowing e and n or even m it can be extremely difficult to find d
### RSA algorithm involves 4 steps:
	# 1. Key generation: 
			# compute p, q, n = p*q, phi(n) = (p-1)*(q-1) such that lcm(n, phi(n)) != 1
			# e = 3 (for this challenge)
			# d = invMod(e, n)
	# 2. Key distribution
		#	Suppose that Bob wants to send information to Alice. If they decide to use RSA, 
		# Bob must know Alice's public key (n, e) to encrypt the message and Alice must use her private key (n, d)
		# to decrypt the message. To enable Bob to send his encrypted messages, Alice transmits her public key to Bob 
		# via a reliable, but not necessarily secret, route. Alice's private key is never distributed.
	# 3. Encryption
			# ciphertext_int = message_int ^ e (mod n)  
	# 4. Decryption
			# message_int = ciphertext_int ^ d (mod n)

import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *


cipher = RSA(1024)
message = "Privacy is just a myth."
ct_int = cipher.encrypt(message)
pt = cipher.decrypt(ct_int)
print "Ciphertext (RSA):",ct_int, "\nPlaintext:", pt


