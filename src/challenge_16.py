### EXPLAIN! EXPLAIN! EXPLAIN!

## WHAT WE HAVE?
	# ciphertext = generate( 
	#		AES_128_CBC_ENC("comment1=cooking%20MCs;userdata=" || payload || ";comment2=%20like%20a%20pound%20of%20bacon")
	#	)
	# output=AES_128_CBC_DEC(ciphertext)
	# Only input in payload
	# ";","=" will be removed from input by generate() function

## GOAL:
	# Output contains ";admin=true;"

## WHAT TO DO?
	# Modify ciphertext -> Break CBC mode cipher
	# How to modify ciphertext? ()
		# Theory: In CBC mode, since we XOR each decrypted block with previous ciphertext block, we can change a byte in plaintext by changing CORRESPONDING byte in previous ciphertext (though this completely corrupts previous plaintext - but we can create a JUNK block to be corrupted) => use this to produce the unescaped characters ";" and "=" in the plaintext!
		# Practice:
			# junk_block = "A" * 16
			# admin_block = "AadminAtrueA"
			# => Change 3 "A" bytes in admin_block with ";","=",";" respectively. How? change ciphertext of each corresponding "A" byte in junk_block, so that after XOR function, we get ";","=",";". Change with what? Here's intersting part.
			# (1) x XOR y = 'A'  || x: ciphertext byte in junk_block, y: decrypted byte
			# (2) z XOR y = ';'  || z: ciphertext byte we need to find
			# (1) XOR (2) => z = x XOR ('A' XOR ';')
			# replace x with z
			# ... same steps with "="
			# ...
			# after changing 3 bytes in ciphertext, we get the EVIL ciphertext = "....z1...z2...z3...."!
			# decrypt it and enjoy! 
			
import sys
sys.path.insert(0, './lib')
from my_crypto_lib import *

import os
from random import randint

def generate(input_string):
	intput_string=input_string.replace(";","").replace("=","")
	string="comment1=cooking%20MCs;userdata="+input_string+";comment2=%20like%20a%20pound%20of%20bacon"
	string=pkcs7_padding(string)
	string_enc=aes_cbc_enc(128,string,key,iv)
	return hex_to_ascii(string_enc)

def make_admin():
	junk_block="A"*16
	admin_block="AadminAtrueA"
	input_str=junk_block+admin_block
	ct=generate(input_str)
	# change 1st "A" -> ";"
	offset=32 # size of prefix
	c = xor(ct[offset], xor("A", ";"))
	ct=ct[:offset]+c+ct[offset+1:]
	# change 2nd "A" -> "="
	c = xor(ct[offset+6], xor("A", "="))
	ct=ct[:offset+6]+c+ct[offset+7:]
	# change 1st "A" -> ";"
	c = xor(ct[offset+11], xor("A", ";"))
	ct=ct[:offset+11]+c+ct[offset+12:]
	return ct
	
def check_admin(ciphertext):
	plaintext=aes_cbc_dec(128,ciphertext,key,iv)
	print plaintext
	return ";admin=true;" in plaintext	

key=os.urandom(16)
iv=os.urandom(16)
ct=make_admin()
if check_admin(ct):
	print "Welcome back, ADMIN!"
else:
	print "Welcome back, USER!"
