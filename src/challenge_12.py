### QUESTIONS!! WHY can't just decrypt the "unknown base64 string" to ascii (in practice)? it says "Base64 decode the string before appending it", so we already have the plaintext before passing it into ECB ecrypting function (call the result of encryption as 'ciphertext0'), then we have to bruteforce "AAAAAAAAAAAAAAAU" (U-unknown) with U from 0(10)->256(10) until we have the same result as 'ciphertext0'? and WHY call the encryption function "oracle"??? 
### Userful articles: https://c0nradsc0rner.com/2016/07/03/ecb-byte-at-a-time/
###					  https://cypher.codes/writing/cryptopals-challenge-set-2

import sys
sys.path.insert(0, './lib')
from my_crypto_lib import *

import os
from random import randint

def aes_ecb_enc_oracle(plaintext,key):
	plaintext=pkcs7_padding(plaintext)
	# ecb encrypt
	ciphertext=aes_ecb_enc(plaintext,key)
	return ciphertext

def aes128_ecb_dec_1byte1(text,rand_key):
	#ciphertext=aes_ecb_enc_oracle(text,rand_key)
	text=pkcs7_padding(text)
	ciphertext_size=len(text)#len(ciphertext0)
	plaintext=""
	junk="A"*ciphertext_size
	for i in range(ciphertext_size):
		plaintext2=plaintext
		# dictionary
		d={}
		for j in range(0,256):
			string=junk[:-(i+1)]+plaintext2+chr(j)
			ct=aes_ecb_enc_oracle(string,rand_key)
			d[string]=ct
		#print ascii_to_hex(ct)
		#break
		short_plaintext="A"*(ciphertext_size-(i+1))
		short_plaintext+=text
		ciphertext2=aes_ecb_enc_oracle(short_plaintext,rand_key)
		#print ascii_to_hex(ciphertext2)
		#break
		for k,v in d.items():
			if ascii_to_hex(ciphertext2[:ciphertext_size])==ascii_to_hex(v):
				#print k
				plaintext=k[-(i+1):]
				#print plaintext
	print plaintext

'''		
# dictionary
d={}
#key = os.urandom(16)
key="YELLOW SUBMARINE"
b64_unknown="Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

#plaintext="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
plaintext="A"*141
plaintext+="RoA"
for i in range(65,122):
	string=plaintext[:-1]+chr(i)
	ct=aes_ecb_enc_oracle(string,key)
	d[string]=ct


#one_byte_short_plaintext="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
short_plaintext="A"*141
#plaintext+=base64_to_ascii(b64_unknown)
short_plaintext+=base64_to_ascii(b64_unknown)

#ciphertext=aes_ecb_enc_oracle(base64_to_ascii(b64_unknown),key)
#print len(ciphertext)
ciphertext2=aes_ecb_enc_oracle(short_plaintext,key)
#print ascii_to_hex(ciphertext2),"\n"

for k,v in d.items():
	if ascii_to_hex(ciphertext2[:144])==ascii_to_hex(v):
		print k
		print ascii_to_hex(v),"\n"
#print ascii_to_hex(ciphertext[16:32])
#print "\n",ascii_to_hex(ciphertext2[:144])
#if detect_aes_ecb(ciphertext2,128)==True:
#	print "ECB baby!"'''

key="YELLOW SUBMARINE"
b64_unknown="Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
aes128_ecb_dec_1byte1(base64_to_ascii(b64_unknown),key)
