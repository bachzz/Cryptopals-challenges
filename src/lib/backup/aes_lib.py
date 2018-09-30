from my_crypto_lib import *
from Crypto.Cipher import AES

### --- AES ENCRYPTION / DECRYPTION --- ###
				
def aes_ecb_enc(message,key):
	cipher=AES.new(key,AES.MODE_ECB)
	return cipher.encrypt(message)

def aes_ecb_dec(ciphertext,key):
	cipher=AES.new(key,AES.MODE_ECB)
	return cipher.decrypt(ciphertext)
	
def detect_aes_ecb(ct_ascii,aes_type):
	byte_size=aes_type/8
	for i in range(0,len(ct_ascii),byte_size):
		if ct_ascii[i:(i+byte_size)] in ct_ascii[(i+byte_size):]:
			return True
	return False
	
def aes_padding(text,pad_byte):
	bytes_size=len(text)
	if bytes_size % 16 != 0:
		aes_len = (bytes_size/16+1)*16
		missing_bytes = aes_len-bytes_size
		for i in range(missing_bytes):
			text+=pad_byte
	return text

def aes_cbc_enc(aes_type,plaintext,key,IV): # return hex
	bytes_size=aes_type/8
	# encrypt 1st block with IV  
	# ciphertext_block_1 = aes_ecb_enc(plaintext_block_1 XOR IV,key) 
	block=plaintext[0:bytes_size]
		# conversion
	block_hex=ascii_to_hex(block)
	IV_hex=ascii_to_hex(IV)
	block_XOR=fixed_XOR(IV_hex,block_hex).zfill(len(IV_hex))
	block_XOR_ascii=hex_to_ascii(block_XOR)
	ciphertext1=aes_ecb_enc(block_XOR_ascii,key)
	ciphertext1_hex=ascii_to_hex(ciphertext1)
		# update ciphertext
	ciphertext=ciphertext1_hex
	# encrypt next blocks with previous block 
	# ciphertext_block_i = aes_ecb_enc(plaintext_block_i XOR ciphertext_block_i-1,key)
	for i in range(bytes_size,len(plaintext),bytes_size):
		block2=plaintext[i:(i+bytes_size)]
			# conversion
		block2_hex=ascii_to_hex(block2)
		block2_XOR=fixed_XOR(ciphertext1_hex,block2_hex).zfill(len(block2_hex))
		block2_XOR_ascii=hex_to_ascii(block2_XOR)
		ciphertext1=aes_ecb_enc(block2_XOR_ascii,key)
		ciphertext1_hex=ascii_to_hex(ciphertext1)
			# update ciphertext
		ciphertext+=ciphertext1_hex
	return ciphertext

def aes_cbc_dec(aes_type, ciphertext, key, IV):	# return ascii
	bytes_size=aes_type/8
	# decrypt 1st block with IV  
	# plaintext_block_1 = IV XOR aes_ecb_dec(ciphertext_block_1,key) 
	block=ciphertext[0:bytes_size]
	block_dec=aes_ecb_dec(block,key)
		# conversion
	block_dec_hex=ascii_to_hex(block_dec)
	IV_hex=ascii_to_hex(IV)
	plaintext=fixed_XOR(IV_hex,block_dec_hex).zfill(len(IV_hex))
	
	# decrypt next blocks with previous block 
	# plaintext_block_i = ciphertext_block_i-1 XOR aes_ecb_dec(ciphertext_block_i,key))
	for i in range(bytes_size,len(ciphertext),bytes_size):
		block2=ciphertext[i:(i+bytes_size)]
		block2_dec=aes_ecb_dec(block2,key)
			# conversion
		block2_dec_hex=ascii_to_hex(block2_dec)
		block_hex=ascii_to_hex(block)
		plaintext+=fixed_XOR(block_hex,block2_dec_hex).zfill(len(block_hex))
			# update previous block
		block=block2
	return hex_to_ascii(plaintext)
