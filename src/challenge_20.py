### EXPLAIN!
## WHAT TO DO?
	# Same as 19
## HOW TO DECRYPT:
	# Concatenate all padded-to-longest-length ciphertexts into 1 string
	# Since each ciphertext is encrypted using the same key -> the whole string is encrypted with repeated-key-xor
	# Use break-repeating-key-xor function in challenge 6 to get the keystream
	# XOR that keystream with each ciphertext to get plaintext

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


def multi_decryption2(ciphertexts):
	# find max length in all ciphertexts
	max_length = 0
	for ct in ciphertexts:
		length = len(ct)
		if length >= max_length:
			max_length = length

	# Concatenate all padded strings into one
	ciphertexts = [text.ljust(max_length, '0') for text in ciphertexts]
	ciphertexts = "".join(ciphertexts)
	
	# Get keystream using break_repeating_key_xor with keysize = 
	result = break_repeating_key_xor(ciphertexts, max_length)
	keystream = result["key"]
	#key = break_xor_repeating_key(ciphertexts,max_length)
	#print key
	return keystream

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

with open("./txt/20.txt") as f:
    b64 = f.read()

b64 = b64.split("\n")[:-1]
key = "YELLOW SUBMARINE" 

ciphertexts = multi_encryption(b64, key, "\x00")
keystream = multi_decryption(ciphertexts)

for ct in ciphertexts:
	plaintext = xor(ct,keystream)
 	print plaintext
