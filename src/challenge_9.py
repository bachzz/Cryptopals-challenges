import sys
sys.path.insert(0, './lib')
from my_crypto_lib import *

text="123456789012"
print "Original:",text

text = pkcs7_padding(text)

print "PKCS#7 16-bytes-padding:",text

