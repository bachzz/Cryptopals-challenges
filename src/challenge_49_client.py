### EXPLAIN!

## Server: verify request with valid MAC to continue transaction (shared key with user)

## Part 1: Client can send IV as a parameter in request  (Default IV: good_iv = "\x00" * 16 in CBC_MAC)
##		- Hacker controls 1's account to get valid MAC for request: normal_msg = "_from=1&to=0&amount=10000"
##		- Generates an evil request: evil_msg = "_from=2&to=0&amount=10000"
##		- creates forged_iv = evil_msg XOR (normal_msg XOR good_iv)
##		- Send normal request (normal_msg) along with forged_iv to get valid MAC for evil request
##			HOW: In server when CBC_MAC encryption happens, 
##				1st step: forged_iv XOR evil_msg[16] = normal_msg XOR good_iv
##				.............
##			=> We receive orginal valid MAC for new evil request!
##
## PART 2: the attacker uses length extension to append an evil string ";0:10000" 
##			to a recipients list in a victim's transaction.
##		The attacker first generates a MAC for a valid message that names him as a recipient.
##		He then intercepts a normal message like "from=2&tx_list=3:5000;4:7000" (hacker doesn't control 2,3,4),  
##		and xors in his own message at the end, causing the resultant MAC to become his own MAC.

import requests
import os
import urlparse
import sys

sys.path.insert(0, './lib')
from my_crypto_lib import *

#### SHARED-SECRET-KEY #####
key = "YELLOW SUBMARINE"   #
############################

def cbc_mac(message, key, iv):
	ct = aes_cbc_enc2(message, key, iv)
	return ct[-16:]

def send_money(message, iv, client_mac):
	queries = "?" + message + "&iv_hex=" + ascii_to_hex(iv) + "&mac_hex=" + ascii_to_hex(client_mac)
	request = requests.post("http://localhost:8888/" + queries)
	if request.status_code == 200:
		print "OK!"
	else:
		print "Not OK!"

def forge_mac_length_extension(normal_mac, bad_msg, iv):
	block = xor(normal_mac, pkcs7_padding(bad_msg))
	return cbc_mac(block, key, iv)

## PART I ##

# Hacker controls 1's account'
normal_iv = "\x00" * AES.block_size
normal_msg = "_from=1&to=0&amount=10000" 
normal_mac = cbc_mac(normal_msg, key, normal_iv)
print "<Hacker controls 1's account>" + "\n" + normal_msg
send_money(normal_msg, normal_iv, normal_mac)

# Hacker attacks 2's account
evil_msg = "_from=2&to=0&amount=10000" # NOTE!!! 2 ids must have same length for this attack to work
												# 		  e.g: "Alice" & "Bobbb"
forced_iv = xor(evil_msg[:16], xor(normal_msg[:16], normal_iv))
print "<Hacker attacks 2's account>" + "\n" + evil_msg
send_money(evil_msg, forced_iv, normal_mac)


## PART II ##
normal_msg = "_from=2&tx_list=3:5000;4:9000"
normal_mac = cbc_mac(normal_msg, key, normal_iv)

bad_msg = ";0:10000"
forged_mac = forge_mac_length_extension(normal_mac, bad_msg, normal_iv)
forged_msg = pkcs7_padding(normal_msg) + pkcs7_padding(bad_msg)

# Simulate server (I can't use server because request.POST method doesn't accept unicode letters - those encrypted pkcs7_padding)
assert forged_mac == cbc_mac(forged_msg, key, normal_iv)
