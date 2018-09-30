import sys
sys.path.insert(0, './lib')
from my_crypto_lib import *

import os
from random import randint

def aes_ecb_cbc_enc_oracle(plaintext):
	key = os.urandom(16)
	IV = os.urandom(16)
	head_block=(os.urandom(randint(5,10)))
	tail_block=(os.urandom(randint(5,10)))
	plaintext=head_block+plaintext+tail_block
	plaintext=aes_padding(plaintext,"\x00")
	mode=randint(1,2)
	if mode==1:
		ciphertext=aes_ecb_enc(plaintext,key)
	else:
		ciphertext=hex_to_ascii(aes_cbc_enc(128,plaintext,key,IV))
	return ciphertext

plaintext="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
print "Plaintext:",plaintext
ciphertext=aes_ecb_cbc_enc_oracle(plaintext)
print "Ciphertext:",ciphertext
if detect_aes_ecb(ciphertext,128):
	print "=> ECB!"
else:
	print "=> CBC!"
