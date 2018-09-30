import sys
sys.path.insert(0, './lib')
from my_crypto_lib import *

text="12345678901234567"
print "Original:",text

text = aes_padding(text,"x")

print "AES 16 bytes-per-block padding:",text
print chr(65)
