### Better explanation for the challenge + solution

## GOAL: Change our email so that the ciphertext from "email=XX..XX&uid=10&role=user" => "email=XX..XX&uid=10&role=admin" (XX..XX is our email input)

## WHAT WE HAVE? "login" page (profile_for(email) function) with input for email + ciphertext (or cookie) for user profile AFTER inputting email + decrypting function (with unknown key - set key as global) to see user profile

## WHAT WE KNOW?
	# This challenge uses AES128 => each block has 16 bytes
	# 2 things in ciphertext NEED to be changed - "XX..XX" and "user"->"admin" => So we need at least 2 blocks (16 bytes each block - but in practice, we don't know which cipher it uses, we need a function to find the block size) to hold each one. Why need separate blocks to hold for each text we want to change? 1 byte is changed -> whole block is changed

## WHAT TO DO?
	# GOAL: Find EVIL ciphertext of "email=XX..XX&uid=10&role=admin" 
	# 3 main steps to do:
		#-STEP1: Get ciphertext1 of 1st block "email=XX..XX&uid=10&role="
			#+STEP1.1: Determine how many "X" to input based on the block size
			#+STEP1.2: Input email = "XX..XX" ("XX..XX" can be any character - "AA..AA")
			#+STEP1.3: Get ciphertext of profile_for(email) (only get padded block of "email=XX..XX&uid=10&role=")
		#-STEP2: Get ciphertext2 of 2nd block "adminPPPPPPPPPPP" (P - padding byte)
			#+STEP2.1: Determine how many "X" to input to push "admin" to 2nd block
			#+STEP2.2: Input email = "XX..XX" || "admin" || padding PKCS7
			#+STEP2.3: Get ciphertext of profile_for(email) (only get 2nd block of 16 bytes)
		#-STEP3: EVIL ciphertext = ciphertext1 || ciphertext2
	# Thanks to ECB's vulnerability (same plaintext '+' same key = same ciphertext), if we have ciphertext of "email=XX..XX&uid=10&role=admin", we ALWAYS have plaintext as "email=XX..XX&uid=10&role=admin" under the same key in session

import sys
sys.path.insert(0, './lib')
from my_crypto_lib import *
import os

# setup - boring stuffs
def string_to_dict(string): # still NO IDEA why this function is needed as described in cryptopals
	d={}
	for i in string.split("&"):
		i=i.split("=")
		d[i[0]]=i[1]
	return d

def profile_for(email):
	email=email.replace("&","");
	email=email.replace("=","");
	profile_string="email="+email+"&uid=10&role=user"
	#profile_dict=string_to_dict(profile_string)
	profile_string=aes_padding(profile_string,"\x00")
	profile_enc=aes_ecb_enc(profile_string,key)
	return profile_enc

def profile_dec(profile_ascii):
	profile=aes_ecb_dec(profile_ascii,key)
	return profile

def get_block_size(enc_func,data):
	ct_length = len(enc_func(data))
	i = 1
	while True:
		data2 = data + "A"*i
		new_ct_length = len(enc_func(data2))
		block_size = new_ct_length - ct_length
		if block_size:
			return block_size
		i += 1
		
# Get EVIL ciphertext for admin profile - cool stuffs!
def get_admin_profile_ct():
	block_size=get_block_size(profile_for,"admin")
	#STEP1: Get ciphertext1 of 1st block "email=XX..XX&uid=10&role="
	cookie="email=&uid=10&role="
	cookie_padded=aes_padding(cookie,"\x00")
	email_len=len(cookie_padded)-len(cookie)
	email="A"*email_len
	ciphertext1=profile_for(email)[:len(cookie_padded)]
	#STEP2: Get ciphertext2 of 2nd block "adminPPPPPPPPPPP" (P - padding byte)
	cookie="email="
	cookie_padded=aes_padding(cookie,"\x00")
	email_len=len(cookie_padded)-len(cookie)
	email="A"*email_len + aes_padding("admin","\x00")
	ciphertext2=profile_for(email)[len(cookie_padded):(len(cookie_padded)+block_size)]
	#STEP3: EVIL ciphertext = ciphertext1 || ciphertext2
	return ciphertext1+ciphertext2


key=os.urandom(16)

print "User's cookie:",profile_dec(profile_for("foo@bar.com"))
ct=get_admin_profile_ct()
print "Hacker's cookie:",profile_dec(ct)
