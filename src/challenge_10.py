import sys
sys.path.insert(0, './lib')
from my_crypto_lib import *

with open("./txt/10.txt") as f:
	b64=f.read()

b64_ascii=base64_to_ascii(b64)
key="YELLOW SUBMARINE"
IV="\x00"*16

plaintext=aes_cbc_dec(128,b64_ascii,key,IV)
print "=> AES CBC mode Decrypted:\n",plaintext
ct=aes_cbc_enc(128,plaintext,key,IV)
print "\n=> AES CBC mode Encrypted:\n",ct
#print base64_to_hex(b64)
