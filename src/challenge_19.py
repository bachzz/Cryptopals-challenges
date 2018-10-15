### EXPLAIN!
## THEORY:
	# Because the CTR nonce wasn't randomized for each encryption, each ciphertext has been encrypted against the same keystream.

## WHAT TO DO? 
	# Function 1: (multiple encryption) take a list of base64 text and encrypt each one then return list of encrypted text
	# Function 2: (multiple decryption) take a list of ciphertexts and find the keystream 

# HOW TO FIND?
	# ciphertext XOR plaintext = keystream
	# ciphertext XOR keystream = plaintext
	# Take the longest ciphertext, brute-force first corresponding plaintext byte then XOR with first ciphertext byte to get corresponding keystream byte X.
	# XOR that keystream byte with the rest corresponding bytes in other ciphertexts to produce corresponding plaintext bytes.
	# Check how "english" those plaintext bytes are -> save score.
	# Brute-force next plaintext byte -> repeat.
	# The keystream byte X with the highest score would be the CORRECT keystream byte.
	# Repeat same process with next bytes
	# Finally, we get the full keystream -> XOR it with each ciphertext to get plaintext

import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *

def multi_encryption(b64_list, key, nonce):
	lines_enc = []
	for line in b64_list:
		line_ascii = base64_to_ascii(line)
		line_enc = aes_ctr_enc(line_ascii, key, "\x00")
		lines_enc.append(line_enc)
	return lines_enc

def multi_decryption(ciphertexts):
	# find max length in all ciphertexts
	max_length = 0
	max_ct = ""
	for ct in ciphertexts:
		length = len(ct)
		if length >= max_length:
			max_length = length
			max_ct = ct
	
	# get keystream
	keystream = ""
	for c_i in range(0, len(max_ct)):
		max_score = 0
		ks_byte = ""
		for p_i in range(32,122):
			k_i = xor(max_ct[c_i], chr(p_i))
			mix_bytes = ""
			for j in range(0, len(ciphertexts)):
				try:
					p_j = xor(ciphertexts[j][c_i], k_i)
					mix_bytes += p_j
				except IndexError:
					continue
			score = englishness(mix_bytes)
			if score >= max_score:
				max_score = score
				ks_byte = k_i
		keystream += ks_byte

	return keystream

with open("./txt/19.txt") as f:
    b64 = f.read()

b64 = b64.split("\n")[:-1]
key = "YELLOW SUBMARINE" 

ciphertexts = multi_encryption(b64, key, "\x00")
keystream = multi_decryption(ciphertexts)

for ct in ciphertexts:
	plaintext = xor(ct,keystream)
	print plaintext
