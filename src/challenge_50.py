### EXPLAIN!!!

## 					Forged msg = evil_msg + (cbc_mac(evil_msg) XOR normal_msg[:16]) + normal_msg[16:]
## CBC-MAC encrypting 1st block: --------- cbc_mac(normal_msg[:16]) --------------- + normal_msg[16:]
## 			.....
## CBC-MAC encrypting n-th block: Forged_mac = normal_mac 

import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *

key = "YELLOW SUBMARINE"



def cbc_mac(message, key, iv = "\x00" * AES.block_size):
	ct = aes_cbc_enc2(message, key, iv)
	return ct[-16:]

normal_msg = "alert('MZA who was that?');\n"
normal_mac = cbc_mac(normal_msg, key)
evil_msg = "alert('Ayo, the Wu is back!');//"

block1 = xor(cbc_mac(evil_msg, key), normal_msg[:16])

forged_msg = evil_msg + block1 + normal_msg[16:]
forged_mac = cbc_mac(forged_msg, key)

print "Forged mac: " + ascii_to_hex(normal_mac)
print "Normal mac: " + ascii_to_hex(forged_mac)

assert forged_mac == normal_mac
