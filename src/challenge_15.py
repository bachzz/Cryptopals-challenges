import sys
sys.path.insert(0, './lib')
from my_crypto_lib import *

string="hello\x04\x04\x04\x04"
print string
result=unpad_pkcs7(string)
print result
