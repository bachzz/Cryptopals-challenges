import sys
sys.path.insert(0, './lib')
from my_crypto_lib import *
	
encoded="1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

print "Encrypted hex:",encoded
result=break_single_byte_xor(encoded,65,122) # Brute-force key from A -> z
print "Single-byte key:",result['key']
print "Decrypted message: ",result['message']
