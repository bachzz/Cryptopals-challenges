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
	
def pkcs7_padding(text):
	bytes_size=len(text)
	if bytes_size % 16 != 0:
		aes_len = (bytes_size/16+1)*16
		missing_bytes = aes_len-bytes_size
		pad_byte=chr(missing_bytes)
		text+=pad_byte*missing_bytes
	return text

def unpad_pkcs7(string):
	pad_byte=string[-1]
	if ord(pad_byte) >= AES.block_size:
		return string
		#raise Exception("Bad PKCS#7 padding.")
	for i in range(len(string)-1,len(string)-ord(pad_byte),-1):
		if string[i]!=string[i-1]:
			raise Exception("Bad PKCS#7 padding.")
	string=string[:-ord(pad_byte)]
	if string[-1]==pad_byte:
		raise Exception("Bad PKCS#7 padding.")
	return string

def aes_cbc_enc(aes_type,plaintext,key,IV): # return hex
	bytes_size=aes_type/8
	# encrypt 1st block with IV  
	block = pkcs7_padding(plaintext[0:bytes_size])
		# conversion
	block_XOR_ascii = xor(block,IV)
	ciphertext1=aes_ecb_enc(block_XOR_ascii,key)
	ciphertext1_hex=ascii_to_hex(ciphertext1)
		# update ciphertext
	ciphertext=ciphertext1_hex
	# encrypt next blocks with previous block 
	for i in range(bytes_size,len(plaintext),bytes_size):
		block2=plaintext[i:(i+bytes_size)]
			# conversion
		block2_hex=ascii_to_hex(block2)
		block2_XOR=fixed_XOR(ciphertext1_hex,block2_hex).zfill(len(block2_hex))
		block2_XOR_ascii = hex_to_ascii(block2_XOR)
		ciphertext1=aes_ecb_enc(block2_XOR_ascii,key)
		ciphertext1_hex=ascii_to_hex(ciphertext1)
			# update ciphertext
		ciphertext+=ciphertext1_hex
	return ciphertext

def aes_cbc_enc2(data, key, iv):
    """Encrypts the given data with AES-CBC, using the given key and iv."""
    ciphertext = b''
    prev = iv

    # Process the encryption block by block
    for i in range(0, len(data), AES.block_size):

        # Always PKCS 7 pad the current plaintext block before proceeding
        curr_plaintext_block = pkcs7_padding(data[i:i + AES.block_size])
        block_cipher_input = xor(curr_plaintext_block, prev)
        encrypted_block = aes_ecb_enc(block_cipher_input, key)
        ciphertext += encrypted_block
        prev = encrypted_block

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

		### CTR mode ###
def aes_ctr_dec(ciphertext,key,nonce):
	blocks = [ ciphertext[i : i + AES.block_size] for i in range(0, len(ciphertext), AES.block_size) ]
	i = 0
	plaintext = ""
	for block in blocks:
		counter = nonce * 8 + chr(i) + "\x00" * 7
		counter_enc = aes_ecb_enc(counter,key)
		plaintext += xor(block,counter_enc)
		i+=1
	return plaintext

def aes_ctr_enc(plaintext,key,nonce):
	blocks = [ plaintext[i : i + AES.block_size] for i in range(0, len(plaintext), AES.block_size) ]
	i = 0
	ciphertext = ""
	for block in blocks:
		counter = nonce * 8 + chr(i) + "\x00" * 7
		counter_enc = aes_ecb_enc(counter, key)
		ciphertext += xor(block, counter_enc)
		i+=1
	return ciphertext