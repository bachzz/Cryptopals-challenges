import sys
sys.path.insert(0, './lib')
from my_crypto_lib import *

import os
from random import randint

def client(buffer):
    buffer=buffer.split("\n")[:-1]
    #j = randint(0,len(buffer)-1)
    j=0
    cookie=buffer[j]
    cookie=base64_to_ascii(cookie)
    cookie=pkcs7_padding(cookie)
    cookie_enc=aes_cbc_enc(128,cookie,key,iv)
    return hex_to_ascii(cookie_enc)
    #print cookie

def padding_oracle(ciphertext,prev_iv):
    print ascii_to_hex(prev_iv),ascii_to_hex(ciphertext)
    plaintext=aes_cbc_dec(128,ciphertext,key,prev_iv)
    try:
        unpad_pkcs7(plaintext)
        return True
    except:
        return False

'''def xor(b1, b2):
    b = bytearray(len(b1))
    for i in range(len(b1)):
        b[i] = b1[i] ^ b2[i]
    return b'''

def xor(ascii1,ascii2): # return ascii
	hex1=ascii_to_hex(ascii1)
	hex2=ascii_to_hex(ascii2)
	return hex_to_ascii(fixed_XOR(hex1,hex2).zfill(len(hex1)))

def crack(ciphertext):
	pt="A"*len(ciphertext)
	#prev_iv=iv
	for block in range(0, len(ciphertext), AES.block_size):
		for i in range(block+AES.block_size-1, block-1,-1):
			#print block,i
			for j in range(0,255):
				guess=chr(j)
				#ciphertext[block+i]=xor(ciphertext[block+i],xor(guess,chr(AES.block_size-i)))
				ciphertext=ciphertext[:i]+xor( xor(ciphertext[i], guess), chr(block+AES.block_size-i) )+ciphertext[i+1:]
				#print len(ciphertext[block:block+AES.block_size])
				prev_iv=ciphertext[block:block+AES.block_size]
				if padding_oracle(ciphertext[block+AES.block_size:block+2*AES.block_size],prev_iv): # !!!!
					#pt[block+i]=guess
					print j,ascii_to_hex(chr(block+AES.block_size-i))
					pt=pt[:i+AES.block_size]+guess+pt[AES.block_size+i+1:]
					break
			for k in range(block+AES.block_size-1,i-1,-1):
				d_k=xor(pt[k],ciphertext[k])
				#ciphertext[block+k]=xor(d_k,chr(AES.block_size-i+1))
				ciphertext=ciphertext[:k]+xor(d_k,chr(block+AES.block_size-i+1))+ciphertext[k+1:]
	print pt
	
'''def crack_block(block, iv):
    plaintext_block = bytearray()
    start_guess = 0
    while len(plaintext_block) < AES.block_size:
        for guess in range(start_guess, 256):
            padding = len(plaintext_block) + 1
            # Copy the IV so we don't corrupt it for future guesses
            corrupted_iv = iv
            for byte in range(1, padding + 1):
                # Use the "correct" guesses of plaintext block bytes
                if byte < padding:
                    corrupted_iv[-byte] =  bytes(xor(
                        xor(
                            [iv[-byte]],
                            chr(plaintext_block[-byte])
                        ),
                        chr(padding)
                    ))
                # Guess the correct byte
                else:
                    corrupted_iv[-byte] =  bytes(xor(
                        xor([iv[-byte]], chr(guess)),
                        chr(padding)
                    ))
            if padding_oracle(block, corrupted_iv):
                # If the padding oracle doesn't complain... we've guessed the
                # correct byte!
                plaintext_block = chr(guess) + plaintext_block
                start_guess = 0
                break
        else:
            # If we cannot find a correct padding, the guess for the previous
            # byte was incorrect... so try another one!
            try:
                start_guess = int(plaintext_block[0]) + 1
                plaintext_block = plaintext_block[1:]
            except:
                # This occurs if the last ciphertext block is just a padding
                # block... I don't know why my encryption is sometimes adding
                # an extra block
                return bytearray()
    return plaintext_block

def crack(ciphertext, iv):
    ciphertext = iv + ciphertext
    plaintext = ''
    for i in range(len(ciphertext) / AES.block_size):
        # We only really need to pass two blocks to the padding oracle...
        # The block to the decrypt, and the one before it which we corrupt
        plaintext += crack_block(
            ciphertext[(i + 1) * AES.block_size: (i + 2) * AES.block_size],
            ciphertext[i * AES.block_size: (i + 1) * AES.block_size]
        )
    return unpad_pkcs7(plaintext)'''
				
with open("./txt/17.txt") as f:
    b64=f.read()


#print test[4]
#print test[:4]+test[4]+test[5:]

key=os.urandom(16)
iv=os.urandom(16)

ct=client(b64)
print ascii_to_hex(ct)
#print server(ct)
#print ct
crack(ct)
#plaintext=crack(ct,iv)
#print plaintext
#test="123456789012345\x03"
#print padding_oracle(test)

