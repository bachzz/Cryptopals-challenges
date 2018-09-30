import sys
sys.path.insert(0, './lib')
from my_crypto_lib import *

with open('./txt/7.txt') as f:
	ciphertext=base64_to_ascii(f.read())
key="YELLOW SUBMARINE"
message=aes_ecb_dec(ciphertext,key)
print message
