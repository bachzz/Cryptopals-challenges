### SIMPLE EXPLANATION
## Goal: Decrypt unknown string byte-by-byte
## WHAT WE HAVE?
	# Ciphertext  AES_128_ECB(random_prefix || user's input || unknown_string)
## WHAT WE KNOW?
	# We can decrypt unknown_string byte-by-byte by repeatedly calling AES_128_ECB with specific input
## WHAT TO DO?
	# Same as challenge 12 + determine "random_prefix" size so that we can pad the input with missing bytes of "random_prefix" to get block-aligned.
	# How to determine "random_prefix" size?
		#1.Create a buffer of block size length
		#2.Concatenate your buffer with itself N times (where N is a large positive integer) and use this as your input to the encryption oracle. For example, if N = 2 and your buffer is "YELLOW SUBMARINE", your input would be "YELLOW SUBMARINEYELLOW SUBMARINE".
		#3.Pass your input to the encryption oracle to obtain a ciphertext. Search the ciphertext for N consecutive identical blocks. The index of the first byte of the N blocks is the beginning of your input and also the length of the random_prefix!
		#4.If you can’t find N consecutive identical blocks in the ciphertext, it’s probably because the random_prefix is not block aligned. Prepend 1 byte to your input and go back to step 3.
		#5.Note: To get the true size of the random_prefix, you must subtract the number of prepended padding bytes.
		#6.If you have prepended block_size - 1 bytes to the input and you still cannot find N consecutive identical blocks, the ciphertext wasn’t encrypted in ECB mode and we’re out of luck.


import sys
sys.path.insert(0, './lib')
from my_crypto_lib import *

import os
from random import randint

def aes_ecb_enc_oracle(plaintext):
	plaintext=aes_padding(plaintext,"\x00")
	ciphertext=aes_ecb_enc(plaintext,key)
	return ciphertext

def count_same_blocks(ciphertext,block_size):
	m=0
	j=0
	max_block=""
	for i in range(0,len(ciphertext),block_size):
		c=ciphertext.count(ciphertext[i:i+block_size])
		if c>=m and max_block!=ciphertext[i:i+block_size]:
			m=c
			j=i
			max_block=ciphertext[i:i+block_size]
	result={"max count":m,"index":j}
	return result

def get_prefix_size(rand_prefix,junk,unknown_text,same_blocks_num,block_size):
	c=0
	i=0
	sample=""
	sample_ct=""
	while c != same_blocks_num:
		sample=rand_prefix+"A"*i+junk+unknown_text
		sample_ct=aes_ecb_enc_oracle(sample)
		c=count_same_blocks(sample_ct,block_size)["max count"]
		i+=1
	return count_same_blocks(sample_ct,block_size)["index"]-i+1

def aes128_ecb_dec_1byte1(text):
	# same as challenge 12
	block_size=get_block_size(aes_ecb_enc_oracle,text)
	text=aes_padding(text,"\x00")
	ciphertext_size=len(text)
	plaintext=""
	junk="A"*ciphertext_size
	# get prefix size
	same_blocks_num= ciphertext_size / block_size
	prefix_size=get_prefix_size(rand_prefix,junk,text,same_blocks_num,block_size)
	prefix_padded_size=prefix_size
	missing_bytes=0
	# same as challenge 12 + some tweaks with missing bytes to get block-aligned 
	if prefix_size % 16 != 0:
		prefix_padded_size = (prefix_size/16+1)*16
		missing_bytes=prefix_padded_size-prefix_size
	for i in range(ciphertext_size):
		plaintext2=plaintext
		# dictionary
		d={}
		for j in range(0,256):
			string=rand_prefix+"A"*missing_bytes+junk[:-(i+1)]+plaintext2+chr(j)
			ct=aes_ecb_enc_oracle(string)
			d[string]=ct
		short_plaintext=rand_prefix+"A"*missing_bytes+"A"*(ciphertext_size-(i+1))+text
		ciphertext2=aes_ecb_enc_oracle(short_plaintext)
		for k,v in d.items():
			if ascii_to_hex(ciphertext2[:prefix_padded_size+ciphertext_size])==ascii_to_hex(v): 
				plaintext=k[-(i+1):]
	return plaintext


key=os.urandom(16)
b64_unknown="Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
rand_prefix=os.urandom(randint(1,16))

print "Random-prefix size:",len(rand_prefix)
result=aes128_ecb_dec_1byte1(base64_to_ascii(b64_unknown))
print "\nUnknown string decrypted byte-by-byte:\n",result
