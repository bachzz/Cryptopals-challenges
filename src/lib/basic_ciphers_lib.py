from my_crypto_lib import *

				### --- BREAK SINGLE-BYTE KEY XOR (Substitution's cipher) --- ###	
	
# chatacters frequency
letter_scores = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }

letter_scores_without_space = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074
    }

def englishness(str):
    score = 0
    for i in range(0, len(str), 1):
        c = str[i].lower()
        if c in letter_scores:
            score += letter_scores[c]
    return score

def englishness2(str):
    score = 0
    for i in range(0, len(str), 1):
        c = str[i].lower()
        if c in letter_scores_without_space:
            score += letter_scores_without_space[c]
    return score

def break_single_byte_xor(encoded,dec_start,dec_end): # dec_start: decimal value of first char
	max_score=0										  # dec_end: decimal value of final char
	true_key=0
	message=0
	for i in range(dec_start,dec_end): # Brute-force key from ascii(dec_start)->ascii(dec_end)
		key=hex(i)[2:]
		result=single_byte_XOR(encoded,key).zfill(len(encoded)).decode("hex")
		if englishness(result)>max_score:
			max_score=englishness(result)
			true_key=key
			message=result
	result={
		# 'key':true_key.decode("hex"),
		'key': hex_to_ascii(true_key.zfill(2)),
		'message':message
	}
	return result

				### --- IMPLEMENT / BREAK REPEATING-KEY XOR (VIGENER's cipher) --- ###

def hamming_distance(hex1,hex2):
	xor=fixed_XOR(hex1,hex2)
	xor_bin=hex_to_binary(xor)
	count=0
	for i in range(len(xor_bin)):
		if xor_bin[i]=="1":
			count+=1
	return count

def find_possible_keysize(encrypted_ascii,min_byte_size,max_byte_size): 
	key_avg_dists=[]
	for keysize in range(min_byte_size,max_byte_size):
		chunks=[encrypted_ascii[i:i+keysize] for i in range(0,len(encrypted_ascii),keysize)]
		norm_dists=[]
		while True:
			try:
				chunk0=chunks[0]
				chunk1=chunks[1]
				if len(chunk0)==len(chunk1):
					# calculate Hamming distance
					chunk0_hex=ascii_to_hex(chunk0)
					chunk1_hex=ascii_to_hex(chunk1)
					dist=hamming_distance(chunk0_hex,chunk1_hex)
					# normalize the distance
					norm=dist/float(keysize)
					norm_dists.append(norm)
				del chunks[0]
				del chunks[0]
			except Exception as e:
				break
		result = {
			'key':keysize,
			'avg distance':sum(norm_dists)/len(norm_dists)
		}
		key_avg_dists.append(result)

	possible_keysize = sorted(key_avg_dists, key=lambda x: x['avg distance'])	
	return possible_keysize[0]['key']

def break_repeating_key_xor(encrypted_ascii,keysize):
	# GET THE KEY!
	key=[]
	for i in range(keysize):
		block=[]
		for j in range(i,len(encrypted_ascii),keysize):
			block.append(encrypted_ascii[j])
		block="".join(block)
		block_hex=ascii_to_hex(block)
		key_char=break_single_byte_xor(block_hex,0,256)['key'] # brute-force from 'SPACE' to ...
		key.append(key_char)
	key="".join(key)
	# GET THE MESSAGE!
	keys=key_dup(key,len(encrypted_ascii)) # duplicate key -> len(keys)=len(ciphertext)
	keys_hex=ascii_to_hex(keys)
	encrypted_hex=ascii_to_hex(encrypted_ascii)
	message_hex=fixed_XOR(encrypted_hex,keys_hex).zfill(len(encrypted_hex))
	message=hex_to_ascii(message_hex)
	result = {
		'key':key,
		'message':message
	}
	return result

			### AES cipher ###

def find_block_length(encryption_oracle):
	"""Returns the length of a block for the block cipher used by the encryption_oracle.
	To find the length of a block, we encrypt increasingly longer plaintexts until the size of the
	output ciphertext increases too. When this happens, we can then easily compute the length of a block
	as the difference between this new length of the ciphertext and its initial one.
	"""
	my_text = ''
	ciphertext = encryption_oracle(my_text)
	initial_len = len(ciphertext)
	new_len = initial_len

	while new_len == initial_len:
		my_text += 'A'
		ciphertext = encryption_oracle(my_text)
		new_len = len(ciphertext)
	return new_len - initial_len


def find_prefix_length(encryption_oracle, block_length):
	"""Returns the length of the prefix that the encryption oracle prepends to every plaintext."""

	# Encrypt two different ciphertexts
	ciphertext_a = encryption_oracle('A')
	ciphertext_b = encryption_oracle('B')

	# Find their common length
	common_len = 0
	while ciphertext_a[common_len] == ciphertext_b[common_len]:
		common_len += 1
	# Make sure that the common length is multiple of the block length
	common_len = int(common_len / block_length) * block_length

	# Try to add an increasing number of common bytes to the plaintext till they until
	# the two ciphertexts will have one extra identical block
	for i in range(1, block_length + 1):
		ciphertext_a = encryption_oracle('A' * i + 'X')
		ciphertext_b = encryption_oracle('A' * i + 'Y')

		# If there is one more identical block, it will mean that by adding i bytes
		# we made the common input (including prefix) to the same length multiple of
		# a block size. Then we can easily get the length of the prefix.
		if ciphertext_a[common_len:common_len + block_length] == ciphertext_b[common_len:common_len + block_length]:
			return common_len + (block_length - i)